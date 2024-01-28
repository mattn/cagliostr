#include "cagliostr.hxx"
#include "version.h"
#include <Server.h>

#include "spdlog/cfg/env.h"
#include "spdlog/common.h"
#include "spdlog/spdlog.h"
#include <argparse/argparse.hpp>

typedef struct subscriber_t {
  std::string sub;
  ws28::Client *client{};
  std::vector<filter_t> filters;
} subscriber_t;

// global variables
std::vector<subscriber_t> subscribers;

static void relay_send(ws28::Client *client, const nlohmann::json &data) {
  assert(client);
  auto s = data.dump();
  spdlog::debug("{} << {}", client->GetIP(), s);
  client->Send(s.data(), s.size(), 1);
}

static inline void relay_notice(ws28::Client *client, const std::string &msg) {
  assert(client);
  nlohmann::json data = {"NOTICE", msg};
  relay_send(client, data);
}

static inline void relay_notice(ws28::Client *client, const std::string &id,
                                const std::string &msg) {
  assert(client);
  nlohmann::json data = {"NOTICE", id, msg};
  relay_send(client, data);
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
  assert(client);
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

  send_records([&](const nlohmann::json &data) { relay_send(client, data); },
               sub, filters, false);
  auto reply = nlohmann::json::array({"EOSE", sub});
  relay_send(client, reply);
}

static void do_relay_count(ws28::Client *client, nlohmann::json &data) {
  assert(client);
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

  send_records([&](const nlohmann::json &data) { relay_send(client, data); },
               sub, filters, true);
}

static void do_relay_close(ws28::Client *client, nlohmann::json &data) {
  assert(client);
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
      if (filter.since > ev.created_at) {
        continue;
      }
    }
    if (filter.until > 0) {
      if (ev.created_at > filter.until) {
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
  try {
    auto ej = data[1];
    event_t ev = {};
    ev.id = ej["id"];
    ev.pubkey = ej["pubkey"];
    ev.content = ej["content"];
    ev.created_at = ej["created_at"];
    ev.kind = ej["kind"];
    ev.tags = ej["tags"];
    ev.sig = ej["sig"];

    if (!check_event(ev)) {
      relay_notice(client, "error: invalid id or signature");
      return;
    }

    if (ev.kind == 5) {
      for (const auto &tag : ev.tags) {
        if (tag.size() >= 2 && tag[0] == "e") {
          for (size_t i = 1; i < tag.size(); i++) {
            if (delete_record_by_id(tag[i]) < 0) {
              return;
            }
          }
        }
      }
    } else {
      if (20000 <= ev.kind && ev.kind < 30000) {
        return;
      } else if (ev.kind == 0 || ev.kind == 3 ||
                 (10000 <= ev.kind && ev.kind < 20000)) {
        if (delete_record_by_kind_and_pubkey(ev.kind, ev.pubkey) < 0) {
          return;
        }
      } else if (30000 <= ev.kind && ev.kind < 40000) {
        std::string d;
        for (const auto &tag : ev.tags) {
          if (tag.size() >= 2 && tag[0] == "d") {
            if (delete_record_by_kind_and_pubkey_and_dtag(ev.kind, ev.pubkey,
                                                          tag) < 0) {
              return;
            }
          }
        }
      }

      if (insert_record(ev) != 1) {
        relay_notice(client, "error: duplicate event");
        return;
      }
    }

    for (const auto &s : subscribers) {
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

static auto nip11 = R"({
  "name": "cagliostr",
  "description": "nostr relay written in C++",
  "pubkey": "2c7cc62a697ea3a7826521f3fd34f0cb273693cbe5e9310f35449f43622a5cdc",
  "contact": "mattn.jp@gmail.com",
  "supported_nips": [1, 2, 4, 9, 11, 12, 15, 16, 20, 22, 33, 42, 45, 50],
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
})"_json;

static void http_request_callback(ws28::HTTPRequest &req,
                                  ws28::HTTPResponse &resp) {
  spdlog::debug("{} >> {} {}", req.ip, req.method, req.path);
  resp.header("Access-Control-Allow-Origin", "*");
  if (req.method == "GET") {
    auto accept = req.headers.Get("accept");
    if (accept.has_value() && accept.value() == "application/nostr+json") {
      resp.status(200);
      resp.header("content-type", "application/json; charset=UTF-8");
      resp.send(nip11.dump());
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
  assert(client);
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
  assert(client);
  assert(data);
  std::string s(data, len);
  spdlog::debug("{} >> {}", client->GetIP(), s);
  try {
    auto payload = nlohmann::json::parse(s);

    if (!payload.is_array() || payload.size() < 2 || !payload[0].is_string()) {
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
  assert(req);
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
  uv_stop(req->loop);
  storage_deinit();
}

static std::string env(const char *name, const char *default_value) {
  assert(name);
  assert(default_value);
  const char *value = std::getenv(name);
  if (value == nullptr) {
    value = default_value;
  }
  return value;
}

static void server(short port) {
  uv_loop_t *loop = uv_default_loop();
  auto server = ws28::Server{loop, nullptr};
  server.SetClientDataCallback(data_callback);
  server.SetClientConnectedCallback(connect_callback);
  server.SetClientDisconnectedCallback(disconnect_callback);
  server.SetCheckTCPConnectionCallback(tcpcheck_callback);
  server.SetMaxMessageSize(65535);
  server.SetCheckConnectionCallback(check_callback);
  server.SetHTTPCallback(http_request_callback);
  server.Listen(port);
  spdlog::info("server started :{}", port);

  uv_signal_t sig;
  uv_signal_init(loop, &sig);
  uv_signal_start(&sig, signal_handler, SIGINT);
  uv_run(loop, UV_RUN_DEFAULT);
}

int main(int argc, char *argv[]) {
  argparse::ArgumentParser program("cagliostr", VERSION);
  try {
    program.add_argument("-database")
        .default_value(env("DATABASE_URL", "./cagliostr.sqlite"))
        .help("connection string")
        .metavar("DATABASE")
        .nargs(1);
    program.add_argument("-loglevel")
        .default_value(env("SPDLOG_LEVEL", "info"))
        .help("log level")
        .metavar("LEVEL")
        .nargs(1);
    program.add_argument("-port")
        .default_value((short)7447)
        .help("port number")
        .metavar("PORT")
        .scan<'i', short>()
        .nargs(1);
    program.parse_args(argc, argv);
  } catch (const std::exception &err) {
    std::cerr << err.what() << std::endl;
    std::cerr << program;
    return 1;
  }

  nip11["version"] = VERSION;

  spdlog::cfg::load_env_levels();
  spdlog::set_level(
      spdlog::level::from_str(program.get<std::string>("-loglevel")));
  storage_init(program.get<std::string>("-database"));

  server(program.get<short>("-port"));
  return 0;
}
