#include <algorithm>
#include <exception>
#include <iostream>
#include <sstream>
#include <string>

#include <libbech32/bech32.h>
#include <nlohmann/json.hpp>
#include <openssl/evp.h>

#include <secp256k1.h>
#include <secp256k1_schnorrsig.h>

#include <sqlite3.h>

#include <Server.h>

class tags_t {
public:
  std::vector<std::vector<std::string>> values;
  void print() {}
};

typedef struct event_t {
  std::string id;
  std::string pubkey;
  std::time_t created_at;
  int kind;
  std::vector<std::vector<std::string>> tags;
  std::string content;
  std::string sig;
} event_t;

typedef struct filter_t {
  std::vector<std::string> ids;
  std::vector<std::string> authors;
  std::vector<int> kinds;
  std::vector<std::vector<std::string>> tags;
  std::time_t since;
  std::time_t until;
} filter_t;

typedef struct subscriber_t {
  ws28::Client *client{};
  std::vector<filter_t> filters;
} subscriber_t;

// global variables
std::map<std::string, subscriber_t> subscribers;
sqlite3 *conn = NULL;

static std::string digest2hex(const uint8_t *data) {
  std::stringstream ss;
  ss << std::hex;
  for (int i = 0; i < 32; ++i) {
    ss << std::setw(2) << std::setfill('0') << (int)data[i];
  }
  return ss.str();
}

static std::vector<uint8_t> hex2bytes(const std::string &hex) {
  std::vector<uint8_t> bytes;
  for (unsigned int i = 0; i < hex.length(); i += 2) {
    std::string s = hex.substr(i, 2);
    auto byte = (uint8_t)strtol(s.c_str(), nullptr, 16);
    bytes.push_back(byte);
  }
  return bytes;
}

static void relay_send(ws28::Client *client, nlohmann::json &data) {
  auto s = data.dump();
  std::cout << "<< " << s << std::endl;
  client->Send(s.data(), s.size());
}

static void relay_final(ws28::Client *client, const std::string &id,
                        const std::string &msg) {
  nlohmann::json data = {"CLOSED", id, msg};
  relay_send(client, data);
  client->Close(0);
}

static bool signature_verify(const std::vector<uint8_t> &bytes_sig,
                             const std::vector<uint8_t> &bytes_pub,
                             const uint8_t *digest) {
#define secp256k1_context_flags                                                \
  (SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY)
  secp256k1_context *ctx = secp256k1_context_create(secp256k1_context_flags);
  secp256k1_xonly_pubkey pub;
  if (!secp256k1_xonly_pubkey_parse(ctx, &pub, bytes_pub.data())) {
    secp256k1_context_destroy(ctx);
    return false;
  }

  auto result = secp256k1_schnorrsig_verify(ctx, bytes_sig.data(), digest,
#ifdef SECP256K1_SCHNORRSIG_EXTRAPARAMS_INIT
                                            32,
#endif
                                            &pub);
  secp256k1_context_destroy(ctx);
  return result;
}

std::string make_in_query(const std::string name, const nlohmann::json& data) {
  auto s = data.dump();
  s = s.substr(1, s.size()-2);
  return " " + name + " in (" + s+ ")";
}

static bool send_records(ws28::Client *client, std::string &sub,
                         std::vector<filter_t> &filters) {
  std::string sql = R"(
    SELECT
      id, pubkey, created_at, kind, tags, content, sig
    FROM event WHERE 1 = 1
  )";

  for (const auto &filter : filters) {
    if (!filter.ids.empty()) {
      sql += " AND " + make_in_query("id", filter.ids);
    }
    if (!filter.authors.empty()) {
      sql += " AND " + make_in_query("pubkey", filter.authors);
    }
    if (!filter.kinds.empty()) {
      sql += " AND " + make_in_query("kinds", filter.kinds);
    }
    if (!filter.tags.empty()) {
      std::string condition;
      for (const auto tag : filter.tags) {
        nlohmann::json data = tag;
        auto s = data.dump();
        if (!condition.empty()) {
          condition += " OR ";
        }
        condition += "tags LIKE '%" + s + "%'";
      }
      sql += " AND (" + condition + ")";
    }
    if (filter.since != 0) {
      std::ostringstream os;
      os << filter.since;
      sql += " AND created_at >= " + os.str();
    }
    if (filter.until != 0) {
      std::ostringstream os;
      os << filter.until;
      sql += " AND created_at <= " + os.str();
    }
  }

  sqlite3_stmt *stmt = nullptr;
  std::cout << sql << std::endl;
  auto ret = sqlite3_prepare(conn, sql.data(), sql.size(), &stmt, nullptr);
  if (ret != SQLITE_OK) {
    fprintf(stderr, "%s\n", sqlite3_errmsg(conn));
    return false;
  }
  while (true) {
    ret = sqlite3_step(stmt);
    if (ret == SQLITE_DONE) {
      break;
    }
    nlohmann::json ej;
    ej["id"] = (char *)sqlite3_column_text(stmt, 0);
    ej["pubkey"] = (char *)sqlite3_column_text(stmt, 1);
    ej["created_at"] = sqlite3_column_int(stmt, 2);
    ej["kind"] = sqlite3_column_int(stmt, 3);
    const unsigned char *j = sqlite3_column_text(stmt, 4);
    ej["tags"] = nlohmann::json::parse(j);
    ej["content"] = (char *)sqlite3_column_text(stmt, 5);
    ej["sig"] = (char *)sqlite3_column_text(stmt, 6);

    nlohmann::json reply = {"EVENT", sub, ej};
    relay_send(client, reply);
  }
  sqlite3_finalize(stmt);

  return true;
}

static void do_relay_req(ws28::Client *client, nlohmann::json &data) {
  std::string sub = data[1];
  if (subscribers.count(sub) != 0) {
    relay_final(client, sub, "error: duplicate subscriber");
    return;
  }
  std::vector<filter_t> filters;
  for (int i = 2; i < data.size(); i++) {
    if (!data[i].is_object()) {
      continue;
    }
    filter_t filter = {
        .since = 0,
        .until = 0,
    };
    if (data[i].count("ids") > 0) {
      for (const auto &id : data[i]["ids"]) {
        filter.ids.push_back(id);
      }
    }
    if (data[i].count("authors") > 0) {
      for (const auto &author : data[i]["authors"]) {
        filter.authors.push_back(author);
      }
    }
    if (data[i].count("kinds") > 0) {
      for (const auto &kind : data[i]["kinds"]) {
        filter.authors.push_back(kind);
      }
    }
    for (nlohmann::json::iterator it = data[i].begin(); it != data[i].end();
         ++it) {
      if (it.key().at(0) == '#' && it.value().is_array()) {
        std::vector<std::string> tag = {it.key().c_str() + 1};
        for (const auto &v : it.value()) {
          tag.push_back(v);
        }
        filter.tags.push_back(tag);
      }
    }
    if (data[i].count("since") > 0) {
      filter.since = data[i]["since"];
    }
    if (data[i].count("until") > 0) {
      filter.until = data[i]["until"];
    }
    filters.push_back(filter);
  }
  subscribers[sub] = {.client = client, .filters = filters};

  send_records(client, sub, filters);
  auto reply = nlohmann::json::array({"EOSE", sub});
  relay_send(client, reply);
}

static void do_relay_close(ws28::Client *client, nlohmann::json &data) {
  std::string sub = data[1];
  if (subscribers.count(sub) == 0) {
    relay_final(client, sub, "error: invalid request");
    return;
  }
  auto ss = subscribers[sub];
  nlohmann::json reply = {"CLOSED", sub, "OK"};
  relay_send(client, reply);
  client->Close(0);
  ss.client->Destroy();
  subscribers.erase(sub);
}

static bool matched_filters(const std::vector<filter_t> &filters,
                            const event_t &ev) {
  auto found = false;
  for (const auto &filter : filters) {
    if (!filter.ids.empty()) {
      auto result = std::find(filter.ids.begin(), filter.ids.end(), ev.id);
      if (result == filter.ids.end()) {
        continue;
      }
    }
    if (!filter.authors.empty()) {
      auto result =
          std::find(filter.authors.begin(), filter.authors.end(), ev.pubkey);
      if (result == filter.authors.end()) {
        continue;
      }
    }
    if (!filter.kinds.empty()) {
      auto result =
          std::find(filter.kinds.begin(), filter.kinds.end(), ev.kind);
      if (result == filter.kinds.end()) {
        continue;
      }
    }
    if (filter.since > 0) {
      if (filter.since <= ev.created_at) {
        continue;
      }
    }
    if (filter.until > 0) {
      if (ev.created_at <= filter.until) {
        continue;
      }
    }
    if (!filter.tags.empty()) {
      auto matched = false;
      for (const auto &tag : ev.tags) {
        if (tag.size() < 2)
          continue;
        for (const auto &filter_tag : filter.tags) {
          if (filter_tag.size() < 2)
            continue;
          if (tag == filter_tag) {
            matched = true;
            break;
          }
        }
        if (matched) {
          break;
        }
      }
      if (!matched) {
        continue;
      }
    }
    found = true;
  }
  return found;
}

static bool insert_record(event_t &ev) {
  const auto sql = R"(
    INSERT INTO event (id, pubkey, created_at, kind, tags, content, sig)
    VALUES ($1, $2, $3, $4, $5, $6, $7)
  )";
  sqlite3_stmt *stmt = nullptr;
  auto ret = sqlite3_prepare(conn, sql, strlen(sql), &stmt, nullptr);
  if (ret != SQLITE_OK) {
    fprintf(stderr, "%s\n", sqlite3_errmsg(conn));
    return false;
  }
  nlohmann::json tags = ev.tags;
  auto s = tags.dump();
  sqlite3_bind_text(stmt, 1, ev.id.data(), ev.id.size(), nullptr);
  sqlite3_bind_text(stmt, 2, ev.pubkey.data(), ev.pubkey.size(), nullptr);
  sqlite3_bind_int(stmt, 3, ev.created_at);
  sqlite3_bind_int(stmt, 4, ev.kind);
  sqlite3_bind_text(stmt, 5, s.data(), s.size(), nullptr);
  sqlite3_bind_text(stmt, 6, ev.content.data(), ev.content.size(), nullptr);
  sqlite3_bind_text(stmt, 7, ev.sig.data(), ev.sig.size(), nullptr);

  ret = sqlite3_step(stmt);
  if (ret != SQLITE_DONE) {
    fprintf(stderr, "%s\n", sqlite3_errmsg(conn));
    sqlite3_free(stmt);
    return false;
  }
  sqlite3_finalize(stmt);

  return true;
}

static void do_relay_event(ws28::Client *client, nlohmann::json &data) {
  auto ej = data[1];
  event_t ev = {};
  try {
    ev.id = ej["id"];
    ev.pubkey = ej["pubkey"];
    ev.content = ej["content"];
    ev.created_at = ej["created_at"];
    ev.kind = ej["kind"];
    ev.tags = ej["tags"];
    ev.sig = ej["sig"];

    const nlohmann::json check = {0,       ev.pubkey, ev.created_at,
                                  ev.kind, ev.tags,   ev.content};
    auto dump = check.dump();

    uint8_t digest[32] = {0};
    EVP_Digest(dump.data(), dump.size(), digest, nullptr, EVP_sha256(),
               nullptr);

    auto id = digest2hex(digest);
    if (id != ev.id) {
      relay_final(client, "", "error: invalid id");
      return;
    }

    auto bytes_sig = hex2bytes(ev.sig);
    auto bytes_pub = hex2bytes(ev.pubkey);
    if (!signature_verify(bytes_sig, bytes_pub, digest)) {
      relay_final(client, "", "error: invalid signature");
      return;
    }

    if (!insert_record(ev)) {
      relay_final(client, "", "error: duplicate event");
      return;
    }

    for (const auto &s : subscribers) {
      if (id == s.first) {
        continue;
      }
      if (matched_filters(s.second.filters, ev)) {
        nlohmann::json reply = {"EVENT", s.first, ej};
        relay_send(s.second.client, reply);
      }
    }
    relay_final(client, "", "OK");
  } catch (std::exception &e) {
    std::cerr << "!! " << e.what() << std::endl;
  }
}

static void http_request_callback(ws28::HTTPRequest &req,
                                  ws28::HTTPResponse &resp) {
  if (req.method == "GET" && req.path == "/") {
    resp.status(200);
    resp.header("content-type", "text/html; charset=UTF-8");
    resp.send("cagliostr\n");
  }
}

static void close_callback(ws28::Client *client) {
  for (auto it = subscribers.begin(); it != subscribers.end(); ++it) {
    if (it->second.client == client) {
      subscribers.erase(it);
      break;
    }
  }
}

static void data_callback(ws28::Client *client, char *data, size_t len,
                          int /*opcode*/) {
  std::string s;
  s.append(data, len);
  std::cout << ">> " << s << std::endl;
  auto payload = nlohmann::json::parse(s);

  if (!payload.is_array() || payload.size() < 2) {
    relay_final(client, "", "error: invalid request");
    return;
  }

  std::string method = payload[0];
  if (payload[0] != "EVENT" && payload[0] != "REQ" && payload[0] != "COUNT" &&
      payload[0] != "CLOSE") {
    relay_final(client, "", "error: invalid request");
    return;
  }
  if (method == "REQ") {
    if (payload.size() < 3) {
      relay_final(client, "", "error: invalid request");
      return;
    }
    do_relay_req(client, payload);
    return;
  }
  if (method == "CLOSE") {
    do_relay_close(client, payload);
    return;
  }
  if (method == "EVENT") {
    do_relay_event(client, payload);
    return;
  }

  client->Close(0);
}

static void signal_handler(uv_signal_t *req, int /*signum*/) {
  uv_signal_stop(req);
  std::cerr << "!! SIGINT" << std::endl;
  for (const auto &[key, value] : subscribers) {
    relay_final(value.client, key, "shutdown...");
  }

  uv_stop(uv_default_loop());
}

static void storage_init() {
  auto ret = sqlite3_open("./cagliostr.sqlite", &conn);
  if (ret != SQLITE_OK) {
    fprintf(stderr, "%s\n", sqlite3_errmsg(conn));
    exit(-1);
  }

  const auto sql = R"(
	CREATE TABLE IF NOT EXISTS event (
       id text NOT NULL,
       pubkey text NOT NULL,
       created_at integer NOT NULL,
       kind integer NOT NULL,
       tags jsonb NOT NULL,
       content text NOT NULL,
       sig text NOT NULL);
	CREATE UNIQUE INDEX IF NOT EXISTS ididx ON event(id);
	CREATE INDEX IF NOT EXISTS pubkeyprefix ON event(pubkey);
	CREATE INDEX IF NOT EXISTS timeidx ON event(created_at DESC);
	CREATE INDEX IF NOT EXISTS kindidx ON event(kind);
	CREATE INDEX IF NOT EXISTS kindtimeidx ON event(kind,created_at DESC);
  )";
  ret = sqlite3_exec(conn, sql, nullptr, nullptr, nullptr);
  if (ret != SQLITE_OK) {
    fprintf(stderr, "%s\n", sqlite3_errmsg(conn));
    exit(-1);
  }
}

int main([[maybe_unused]] int argc, [[maybe_unused]] char *argv[]) {
  storage_init();

  uv_loop_t *loop = uv_default_loop();
  ws28::Server server{loop, nullptr};
  server.SetClientDataCallback(data_callback);
  server.SetClientDisconnectedCallback(close_callback);
  server.SetHTTPCallback(http_request_callback);
  server.Listen(7447);

  uv_signal_t sig;
  uv_signal_init(loop, &sig);
  uv_signal_start(&sig, signal_handler, SIGINT);
  uv_run(uv_default_loop(), UV_RUN_DEFAULT);
  return 0;
}
