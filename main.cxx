#include "cagliostr.hxx"
#include "spdlog/common.h"
#include "spdlog/spdlog.h"
#include <argparse/argparse.hpp>

// global variables
std::vector<subscriber_t> subscribers;
sqlite3 *conn = nullptr;
uv_loop_t *loop = nullptr;

static inline std::string digest2hex(const uint8_t *data) {
  std::stringstream ss;
  ss << std::hex;
  for (int i = 0; i < 32; ++i) {
    ss << std::setw(2) << std::setfill('0') << (int)data[i];
  }
  return ss.str();
}

static inline std::vector<uint8_t> hex2bytes(const std::string &hex) {
  std::vector<uint8_t> bytes;
  for (unsigned int i = 0; i < hex.length(); i += 2) {
    std::string s = hex.substr(i, 2);
    auto byte = (uint8_t)strtol(s.c_str(), nullptr, 16);
    bytes.push_back(byte);
  }
  return bytes;
}

void relay_send(ws28::Client *client, const nlohmann::json &data) {
  auto s = data.dump();
  spdlog::debug("{} << {}", client->GetIP(), s);
  client->Send(s.data(), s.size(), 1);
}

static inline void relay_notice(ws28::Client *client, const std::string &msg) {
  nlohmann::json data = {"NOTICE", msg};
  relay_send(client, data);
}

static inline void relay_notice(ws28::Client *client, const std::string &id,
                                const std::string &msg) {
  nlohmann::json data = {"NOTICE", id, msg};
  relay_send(client, data);
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

static void make_filter(filter_t &filter, nlohmann::json &data) {
  if (data.count("ids") > 0) {
    for (const auto &id : data["ids"]) {
      filter.ids.push_back(id);
    }
  }
  if (data.count("authors") > 0) {
    for (const auto &author : data["authors"]) {
      filter.authors.push_back(author);
    }
  }
  if (data.count("kinds") > 0) {
    for (const auto &kind : data["kinds"]) {
      filter.kinds.push_back(kind);
    }
  }
  for (nlohmann::json::iterator it = data.begin(); it != data.end(); ++it) {
    if (it.key().at(0) == '#' && it.value().is_array()) {
      std::vector<std::string> tag = {it.key().c_str() + 1};
      for (const auto &v : it.value()) {
        tag.push_back(v);
      }
      filter.tags.push_back(tag);
    }
  }
  if (data.count("since") > 0) {
    filter.since = data["since"];
  }
  if (data.count("until") > 0) {
    filter.until = data["until"];
  }
  if (data.count("limit") > 0) {
    filter.limit = data["limit"];
  }
  if (data.count("search") > 0) {
    filter.search = data["search"];
  }
}

static void do_relay_req(ws28::Client *client, nlohmann::json &data) {
  std::string sub = data[1];
  std::vector<filter_t> filters;
  for (size_t i = 2; i < data.size(); i++) {
    if (!data[i].is_object()) {
      continue;
    }
    try {
      filter_t filter;
      make_filter(filter, data[i]);
      filters.push_back(filter);
    } catch (std::exception &e) {
      spdlog::warn("!! {}", e.what());
    }
  }
  if (filters.empty()) {
    auto reply =
        nlohmann::json::array({"NOTICE", sub, "error: invalid filter"});
    relay_send(client, reply);
    return;
  }
  subscribers.push_back({.sub = sub, .client = client, .filters = filters});

  send_records(client, sub, filters, false);
  auto reply = nlohmann::json::array({"EOSE", sub});
  relay_send(client, reply);
}

static void do_relay_count(ws28::Client *client, nlohmann::json &data) {
  std::string sub = data[1];
  std::vector<filter_t> filters;
  for (size_t i = 2; i < data.size(); i++) {
    if (!data[i].is_object()) {
      continue;
    }
    try {
      filter_t filter;
      make_filter(filter, data[i]);
      filters.push_back(filter);
    } catch (std::exception &e) {
      spdlog::warn("!! {}", e.what());
    }
  }
  if (filters.empty()) {
    auto reply =
        nlohmann::json::array({"NOTICE", sub, "error: invalid filter"});
    relay_send(client, reply);
    return;
  }

  send_records(client, sub, filters, true);
}

static void do_relay_close(ws28::Client *client, nlohmann::json &data) {
  std::string sub = data[1];
  auto it = subscribers.begin();
  while (it != subscribers.end()) {
    if (it->sub == sub && it->client == client) {
      it = subscribers.erase(it);
    } else {
      it++;
    }
  }
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
      relay_notice(client, "error: invalid id");
      return;
    }

    auto bytes_sig = hex2bytes(ev.sig);
    auto bytes_pub = hex2bytes(ev.pubkey);
    if (!signature_verify(bytes_sig, bytes_pub, digest)) {
      relay_notice(client, "error: invalid signature");
      return;
    }

    if (ev.kind == 5) {
      for (const auto &tag : ev.tags) {
        if (tag.size() >= 2 && tag[0] == "e") {
          for (size_t i = 1; i < tag.size(); i++) {
            delete_record_by_id(tag[i]);
          }
        }
      }
    } else {
      if (20000 <= ev.kind && ev.kind < 30000) {
        return;
      } else if (ev.kind == 0 || ev.kind == 3 ||
                 (10000 <= ev.kind && ev.kind < 20000)) {
        if (delete_record_by_kind_and_pubkey(ev.kind, ev.pubkey)) {
          insert_record(ev);
        }
      } else if (30000 <= ev.kind && ev.kind < 40000) {
        std::string d;
        for (const auto &tag : ev.tags) {
          if (tag.size() >= 2 && tag[0] == "d") {
            delete_record_by_kind_and_pubkey_and_dtag(ev.kind, ev.pubkey, tag);
          }
        }
      }

      if (!insert_record(ev)) {
        relay_notice(client, "error: duplicate event");
        return;
      }
    }

    for (const auto &s : subscribers) {
      if (s.client == client) {
        continue;
      }
      if (matched_filters(s.filters, ev)) {
        nlohmann::json reply = {"EVENT", s.sub, ej};
        relay_send(s.client, reply);
      }
    }
    nlohmann::json reply = {"OK", ev.id, true, ""};
    relay_send(client, reply);
  } catch (std::exception &e) {
    spdlog::warn("!! {}", e.what());
  }
}

static void http_request_callback(ws28::HTTPRequest &req,
                                  ws28::HTTPResponse &resp) {
  const static auto nip11 = R"(
{
  "name": "cagliostr",
  "description": "nostr relay written in C++",
  "pubkey": "2c7cc62a697ea3a7826521f3fd34f0cb273693cbe5e9310f35449f43622a5cdc",
  "contact": "mattn.jp@gmail.com",
  "supported_nips": [
    1,
    2,
    4,
    9,
    11,
    12,
    15,
    16,
    20,
    22,
    33,
    42,
    45,
    50
  ],
  "software": "https://github.com/mattn/cagliostr",
  "version": "develop",
  "limitation": {
    "max_message_length": 524288,
    "max_subscriptions": 20,
    "max_filters": 10,
    "max_limit": 500,
    "max_subid_length": 100,
    "max_event_tags": 100,
    "max_content_length": 16384,
    "min_pow_difficulty": 30,
    "auth_required": false,
    "payment_required": false,
    "restricted_writes": false
  },
  "fees": {},
  "icon": "https://mattn.github.io/assets/image/mattn-mohawk.webp"
}
      )";

  resp.header("Access-Control-Allow-Origin", "*");
  if (req.method == "GET") {
    auto accept = req.headers.Get("accept");
    if (accept.has_value() && accept.value() == "application/nostr+json") {
      resp.status(200);
      resp.header("content-type", "application/json; charset=UTF-8");
      auto data = nlohmann::json::parse(nip11);
      data["version"] = VERSION;
      resp.send(data.dump());
    } else if (req.path == "/") {
      resp.status(200);
      resp.header("content-type", "text/html; charset=UTF-8");
      resp.send("Cagliostr\n");
    } else {
      resp.status(404);
      resp.header("content-type", "text/html; charset=UTF-8");
      resp.send("Not Found\n");
    }
  }
}

static void connect_callback(ws28::Client * /*client*/,
                             ws28::HTTPRequest &req) {
  spdlog::debug("CONNECTED {}", req.ip);
}

static bool tcpcheck_callback(std::string_view ip, bool secure) {
  spdlog::debug("TCPCHECK {} {}", ip, secure);
  return true;
}

static bool check_callback(ws28::Client * /*client*/, ws28::HTTPRequest &req) {
  spdlog::debug("CHECK {}", req.ip);
  return true;
}

static void disconnect_callback(ws28::Client *client) {
  spdlog::debug("DISCONNECT {}", client->GetIP());
  auto it = subscribers.begin();
  while (it != subscribers.end()) {
    if (it->client == client) {
      it = subscribers.erase(it);
    } else {
      it++;
    }
  }
}

static inline bool check_method(std::string &method) {
  return method == "EVENT" || method == "REQ" || method == "COUNT" ||
         method == "CLOSE";
}

static void data_callback(ws28::Client *client, char *data, size_t len,
                          int /*opcode*/) {
  std::string s(data, len);
  spdlog::debug("{} >> {}", client->GetIP(), s);
  try {
    auto payload = nlohmann::json::parse(s);

    if (!payload.is_array() || payload.size() < 2) {
      relay_notice(client, "error: invalid request");
      return;
    }

    std::string method = payload[0];
    if (!check_method(method)) {
      relay_notice(client, payload[1], "error: invalid request");
      return;
    }
    if (method == "REQ") {
      if (payload.size() < 3) {
        relay_notice(client, payload[1], "error: invalid request");
        return;
      }
      do_relay_req(client, payload);
      return;
    }
    if (method == "COUNT") {
      if (payload.size() < 3) {
        relay_notice(client, payload[1], "error: invalid request");
        return;
      }
      do_relay_count(client, payload);
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
    relay_notice(client, payload[1], "error: invalid request");
  } catch (std::exception &e) {
    spdlog::warn("!! {}", e.what());
    relay_notice(client, std::string("error: ") + e.what());
  }
}

static void signal_handler(uv_signal_t *req, int /*signum*/) {
  uv_signal_stop(req);
  spdlog::warn("!! SIGINT");
  for (auto &s : subscribers) {
    if (s.client == nullptr) {
      continue;
    }
    relay_notice(s.client, s.sub, "shutdown...");
    s.client->Close(0);
    s.client->Destroy();
    s.client = nullptr;
  }
  uv_stop(loop);
  sqlite3_close_v2(conn);
}

using commandtype = std::function<void(
    const std::string &, std::vector<std::string>::const_iterator,
    std::vector<std::string>::const_iterator)>;

static std::string dsn() {
  const char *dsn = getenv("DATABASE_URL");
  if (dsn == nullptr) {
    dsn = "./cagliostr.sqlite";
  }
  return dsn;
}

int main(int argc, char *argv[]) {
  argparse::ArgumentParser program("cagliostr", VERSION);
  try {
    program.add_argument("-database")
        .default_value(dsn())
        .help("connection string")
        .metavar("DATABASE")
        .nargs(1);
    program.add_argument("-loglevel")
        .default_value("info")
        .help("log level")
        .metavar("LEVEL")
        .nargs(1);
    program.parse_args(argc, argv);
  } catch (const std::exception &err) {
    std::cerr << err.what() << std::endl;
    std::cerr << program;
    return 1;
  }

  spdlog::cfg::load_env_levels();

  spdlog::set_level(
      spdlog::level::from_str(program.get<std::string>("-loglevel")));
  storage_init(program.get<std::string>("-database"));

  loop = uv_default_loop();
  auto server = ws28::Server{loop, nullptr};
  server.SetClientDataCallback(data_callback);
  server.SetClientConnectedCallback(connect_callback);
  server.SetClientDisconnectedCallback(disconnect_callback);
  server.SetCheckTCPConnectionCallback(tcpcheck_callback);
  server.SetMaxMessageSize(SIZE_MAX);
  server.SetCheckConnectionCallback(check_callback);
  server.SetHTTPCallback(http_request_callback);
  server.Listen(7447);
  spdlog::info("server started :7447");

  uv_signal_t sig;
  uv_signal_init(loop, &sig);
  uv_signal_start(&sig, signal_handler, SIGINT);
  uv_run(loop, UV_RUN_DEFAULT);
  return 0;
}
