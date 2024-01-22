#include <algorithm>
#include <exception>
#include <iostream>
#include <string>

#include <libbech32/bech32.h>
#include <nlohmann/json.hpp>
#include <openssl/evp.h>

#include <secp256k1.h>
#include <secp256k1_schnorrsig.h>

#include <Server.h>

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

std::map<std::string, subscriber_t> subscribers;

static std::string bytes2hex(const uint8_t *data, const int len) {
  std::stringstream ss;
  ss << std::hex;
  for (int i = 0; i < len; ++i)
    ss << std::setw(2) << std::setfill('0') << (int)data[i];
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

static bool signature_verify(const std::vector<uint8_t> &bytessig,
                             const std::vector<uint8_t> &bytespub,
                             const uint8_t *digest) {
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                                    SECP256K1_CONTEXT_VERIFY);
  secp256k1_xonly_pubkey pub;
  if (!secp256k1_xonly_pubkey_parse(ctx, &pub, bytespub.data())) {
    secp256k1_context_destroy(ctx);
    return false;
  }

  auto result = secp256k1_schnorrsig_verify(ctx, bytessig.data(), digest,
#ifdef SECP256K1_SCHNORRSIG_EXTRAPARAMS_INIT
                                            32,
#endif
                                            &pub);
  secp256k1_context_destroy(ctx);
  return result;
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
  auto eose = nlohmann::json::array({"EOSE", sub});
  relay_send(client, eose);
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
        for (const auto &mtag : filter.tags) {
          if (mtag.size() < 2)
            continue;
          if (tag == mtag) {
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

    auto id = bytes2hex(digest, sizeof(digest));
    if (id != ev.id) {
      relay_final(client, "", "error: invalid id");
      return;
    }

    auto bytessig = hex2bytes(ev.sig);
    auto bytespub = hex2bytes(ev.pubkey);
    if (!signature_verify(bytessig, bytespub, digest)) {
      relay_final(client, "", "error: invalid signature");
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

int main(int argc, char *argv[]) {
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
