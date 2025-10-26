#define INITIALIZE_LOGGER

#include "Headers.h"
#include "cagliostr.hxx"
#include "version.h"
#include <Server.h>

#include <iomanip>
#include <random>
#include <sstream>
#include <memory>
#include <unordered_map>

#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#endif

#include <argparse/argparse.hpp>

using subscriber_t = struct subscriber_t {
  std::string sub;
  ws28::Client *client{};
  std::vector<filter_t> filters;
};

using client_t = struct client_t {
  std::string ip;
  std::string challenge;
  std::string pubkey;
};

// global variables
static std::vector<subscriber_t> subscribers;

static std::string service_url;

static storage_context_t storage_ctx;

static std::unordered_map<ws28::Client*, std::unique_ptr<client_t>> clients_map;

static const std::string realIP(ws28::Client *client) {
  client_t *ci = static_cast<client_t*>(client->GetUserData());
  if (ci != nullptr)
    return ci->ip;
  return client->GetIP();
}

static const std::string realIP(ws28::HTTPRequest &req) {
  std::string ip{req.ip};
  auto value = req.headers.Get("x-forwarded-for");
  if (value.has_value()) {
    ip = value.value().substr(0, value.value().find(','));
  } else {
    value = req.headers.Get("x-real-ip");
    if (value.has_value()) {
      ip = value.value();
    }
  }
  return ip;
}

static const std::string challenge(ws28::Client *client) {
  client_t *ci = static_cast<client_t*>(client->GetUserData());
  if (ci != nullptr)
    return ci->challenge;
  return "";
}

static void set_auth_pubkey(ws28::Client *client, std::string pubkey) {
  client_t *ci = static_cast<client_t*>(client->GetUserData());
  if (ci != nullptr)
    ci->pubkey = pubkey;
}

static bool check_auth_pubkey(ws28::Client *client, std::string pubkey) {
  client_t *ci = static_cast<client_t*>(client->GetUserData());
  if (ci != nullptr)
    return ci->pubkey == pubkey;
  return false;
}

static void relay_send(ws28::Client *client, const nlohmann::json &data) {
  assert(client);
  const auto &s = data.dump();
  console->debug("{} << {}", realIP(client), s);
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

static inline void relay_closed(ws28::Client *client, const std::string &msg) {
  assert(client);
  nlohmann::json data = {"CLOSED", msg};
  relay_send(client, data);
  client->Close(0);
}

static inline void relay_closed(ws28::Client *client, const std::string &id,
                                const std::string &msg) {
  assert(client);
  nlohmann::json data = {"CLOSED", id, msg};
  relay_send(client, data);
}

static inline std::string to_lower(std::string s) {
  std::transform(s.begin(), s.end(), s.begin(),
                 [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  return s;
}

static bool is_hex(const std::string &s, size_t len) {
  if (s.size() != len) {
    return false;
  }
  for (const auto &c : s) {
    if (!std::isxdigit(static_cast<unsigned char>(c))) {
      return false;
    }
  }
  return true;
}

static bool make_filter(filter_t &filter, const nlohmann::json &data) {
  if (data.count("ids") > 0) {
    if (!data["ids"].is_array()) {
      console->warn("make_filter: ids must be array");
      return false;
    }
    for (const auto &id : data["ids"]) {
      if (!id.is_string()) {
        console->warn("make_filter: ids elements must be string");
        return false;
      }
      auto idstr = id.get<std::string>();
      if (!is_hex(idstr, 64)) {
        console->warn("make_filter: ids element invalid hex/length: {}", idstr);
        return false;
      }
      filter.ids.push_back(to_lower(idstr));
    }
  }
  if (data.count("authors") > 0) {
    if (!data["authors"].is_array()) {
      console->warn("make_filter: authors must be array");
      return false;
    }
    for (const auto &author : data["authors"]) {
      if (!author.is_string()) {
        console->warn("make_filter: authors elements must be string");
        return false;
      }
      auto authorstr = author.get<std::string>();
      if (!is_hex(authorstr, 64)) {
        console->warn("make_filter: authors element invalid hex/length: {}", authorstr);
        return false;
      }
      filter.authors.push_back(to_lower(authorstr));
    }
  }
  if (data.count("kinds") > 0) {
    if (!data["kinds"].is_array()) {
      console->warn("make_filter: kinds must be array");
      return false;
    }
    for (const auto &kind : data["kinds"]) {
      if (!kind.is_number_integer()) {
        console->warn("make_filter: kinds elements must be integer");
        return false;
      }
      filter.kinds.push_back(kind.get<int>());
    }
  }
  for (auto it = data.cbegin(); it != data.cend(); ++it) {
    if (!it.key().empty() && it.key().front() == '#' && it.value().is_array()) {
      std::vector<std::string> tag = {it.key().substr(1)};
      for (const auto &v : it.value()) {
        if (!v.is_string()) {
          console->warn("make_filter: tag {} elements must be string", it.key());
          return false;
        }
        tag.push_back(v.get<std::string>());
      }
      filter.tags.push_back(tag);
    }
  }
  if (data.count("since") > 0) {
    if (!data["since"].is_number_integer()) {
      console->warn("make_filter: since must be integer");
      return false;
    }
    filter.since = data["since"].get<long long>();
  }
  if (data.count("until") > 0) {
    if (!data["until"].is_number_integer()) {
      console->warn("make_filter: until must be integer");
      return false;
    }
    filter.until = data["until"].get<long long>();
  }
  if (data.count("limit") > 0) {
    if (!data["limit"].is_number_integer()) {
      console->warn("make_filter: limit must be integer");
      return false;
    }
    filter.limit = data["limit"].get<int>();
  }
  if (data.count("search") > 0) {
    if (!data["search"].is_string()) {
      console->warn("make_filter: search must be string");
      return false;
    }
    filter.search = data["search"].get<std::string>();
  }
  return true;
}

static void do_relay_req(ws28::Client *client, const nlohmann::json &data) {
  assert(client);
  std::string sub = data[1];
  std::vector<filter_t> filters;
  for (size_t i = 2; i < data.size(); i++) {
    if (!data[i].is_object()) {
      continue;
    }
    try {
      filter_t filter;
      if (!make_filter(filter, data[i])) {
        continue;
      }
      filters.push_back(filter);
    } catch (const std::exception &e) {
      console->warn("!! Exception in make_filter: {}", e.what());
      throw;
    }
  }
  if (filters.empty()) {
    const auto reply =
        nlohmann::json::array({"NOTICE", sub, "error: invalid filter"});
    relay_send(client, reply);
    return;
  }
  subscribers.push_back({.sub = sub, .client = client, .filters = filters});

  storage_ctx.send_records(
      [&](const nlohmann::json &_data) { relay_send(client, _data); }, sub,
      filters, false);
  const auto reply = nlohmann::json::array({"EOSE", sub});
  relay_send(client, reply);
}

static void do_relay_count(ws28::Client *client, const nlohmann::json &data) {
  assert(client);
  std::string sub = data[1];
  std::vector<filter_t> filters;
  for (size_t i = 2; i < data.size(); i++) {
    if (!data[i].is_object()) {
      filters.clear();
      break;
    }
    try {
      filter_t filter;
      if (!make_filter(filter, data[i])) {
        filters.clear();
        break;
      }
      filters.push_back(filter);
    } catch (std::exception &e) {
      console->warn("!! {}", e.what());
    }
  }
  if (filters.empty()) {
    const auto reply =
        nlohmann::json::array({"NOTICE", sub, "error: invalid filter"});
    relay_send(client, reply);
    return;
  }

  storage_ctx.send_records(
      [&](const nlohmann::json &_data) { relay_send(client, _data); }, sub,
      filters, true);
}

static void do_relay_close(ws28::Client *client, const nlohmann::json &data) {
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
      const auto result =
          std::find(filter.ids.begin(), filter.ids.end(), ev.id);
      if (result == filter.ids.end()) {
        continue;
      }
    }
    if (!filter.authors.empty()) {
      const auto result =
          std::find(filter.authors.begin(), filter.authors.end(), ev.pubkey);
      if (result == filter.authors.end()) {
        continue;
      }
    }
    if (!filter.kinds.empty()) {
      const auto result =
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

static void to_json(nlohmann::json &j, const event_t &e) {
  j = nlohmann::json{
      {"id", e.id},           {"pubkey", e.pubkey},
      {"content", e.content}, {"created_at", e.created_at},
      {"kind", e.kind},       {"tags", e.tags},
      {"sig", e.sig},
  };
}

static void from_json(const nlohmann::json &j, event_t &e) {
  j.at("id").get_to(e.id);
  j.at("pubkey").get_to(e.pubkey);
  j.at("content").get_to(e.content);
  j.at("created_at").get_to(e.created_at);
  j.at("kind").get_to(e.kind);
  j.at("tags").get_to(e.tags);
  j.at("sig").get_to(e.sig);
}

static void do_relay_event(ws28::Client *client, const nlohmann::json &data) {
  try {
    const event_t ev = data[1];
    if (!check_event(ev)) {
      relay_notice(client, "error: invalid id or signature");
      return;
    }

    for (const auto &tag : ev.tags) {
      if (tag.size() == 1 && tag[0] == "-") {
        if (!check_auth_pubkey(client, ev.pubkey)) {
          const auto reply = nlohmann::json::array(
              {"OK", ev.id, false, "auth-required: authentication required"});
          relay_send(client, reply);
          return;
        }
      }
    }

    if (ev.kind == 5) {
      for (const auto &tag : ev.tags) {
        if (tag.size() >= 2 && tag[0] == "e") {
          for (size_t i = 1; i < tag.size(); i++) {
            if (storage_ctx.delete_record_by_id(tag[i]) < 0) {
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
        if (storage_ctx.delete_record_by_kind_and_pubkey(ev.kind, ev.pubkey,
                                                         ev.created_at) < 0) {
          return;
        }
      } else if (30000 <= ev.kind && ev.kind < 40000) {
        std::string d;
        for (const auto &tag : ev.tags) {
          if (tag.size() >= 2 && tag[0] == "d") {
            if (storage_ctx.delete_record_by_kind_and_pubkey_and_dtag(
                    ev.kind, ev.pubkey, tag, ev.created_at) < 0) {
              return;
            }
          }
        }
      }

      if (storage_ctx.insert_record(ev) != 1) {
        relay_notice(client, "error: duplicate event");
        return;
      }
    }

    for (const auto &s : subscribers) {
      if (matched_filters(s.filters, ev)) {
        nlohmann::json reply = {"EVENT", s.sub, ev};
        relay_send(s.client, reply);
      }
    }
    nlohmann::json reply = {"OK", ev.id, true, ""};
    relay_send(client, reply);
  } catch (std::exception &e) {
    console->warn("!! {}", e.what());
  }
}

static void do_relay_auth(ws28::Client *client, const nlohmann::json &data) {
  try {
    const event_t ev = data[1];
    if (!check_event(ev)) {
      relay_notice(client, "error: invalid id or signature");
      return;
    }

    auto cc = challenge(client);
    auto ok = 0;
    for (const auto &tag : ev.tags) {
      if (tag.size() < 2)
        continue;
      if (tag[0] == "challenge") {
        if (tag[1] == cc)
          ok++;
      }
      if (tag[0] == "relay") {
        auto s = tag[1];
        while (!s.empty() && s.back() == '/')
          s.pop_back();
        if (s == service_url)
          ok++;
      }
    }

    if (ok == 2) {
      set_auth_pubkey(client, ev.pubkey);
      nlohmann::json reply = {"OK", ev.id, true, ""};
      relay_send(client, reply);
      return;
    }

    nlohmann::json reply = {"OK", ev.id, false,
                            "error: failed to authenticate"};
    relay_send(client, reply);
  } catch (std::exception &e) {
    console->warn("!! {}", e.what());
  }
}

static auto html = R"(
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8"/>
<title>Cagliostr</title>
<style>
#content {
  margin: 50vh auto 0;
  transform: translateY(-50%);
  padding: 15px 30px;
  text-align: center;
  font-size: 2em;
}
</style>
</head>
<body>
<div id="content">
<p>Cagliostr the Nostr relay server</p>
<p><img src="https://raw.githubusercontent.com/mattn/cagliostr/main/cagliostr.png" /></p>
</div>
</body>
</html>
)";

static auto nip11 = nlohmann::json{
    {"name", "cagliostr"},
    {"description", "Nostr relay written in C++"},
    {"pubkey", "2c7cc62a697ea3a7826521f3fd34f0cb273693cbe5e9310f35449f43622a5cdc"},
    {"contact", "mattn.jp@gmail.com"},
    {"supported_nips", nlohmann::json::array({1, 2, 4, 9, 11, 12, 15, 16, 20, 22, 28, 33, 40, 42, 45, 50, 70})},
    {"software", "https://github.com/mattn/cagliostr"},
    {"version", VERSION},
    {"limitation", nlohmann::json{
        {"max_message_length", 1024*1024},
        {"max_subscriptions", 20},
        {"max_filters", 10},
        {"max_limit", 500},
        {"max_subid_length", 100},
        {"max_event_tags", 100},
        {"max_content_length", 16384},
        {"min_pow_difficulty", 30},
        {"auth_required", false},
        {"payment_required", false},
        {"restricted_writes", false}
    }},
    {"fees", nlohmann::json::object()},
    {"icon", "https://raw.githubusercontent.com/mattn/cagliostr/main/cagliostr.png"}
};

static void http_request_callback(ws28::HTTPRequest &req,
                                  ws28::HTTPResponse &resp) {
  console->debug("{} >> {} {}", realIP(req), req.method, req.path);
  resp.header("Access-Control-Allow-Origin", "*");
  if (req.method == "GET") {
    const auto accept = req.headers.Get("accept");
    if (accept.has_value() && accept.value() == "application/nostr+json") {
      resp.status(200);
      resp.header("content-type", "application/json; charset=UTF-8");
      resp.send(nip11.dump());
    } else if (req.path == "/") {
      resp.status(200);
      resp.header("content-type", "text/html; charset=UTF-8");
      resp.send(html);
    } else {
      resp.status(404);
      resp.header("content-type", "text/html; charset=UTF-8");
      resp.send("Not Found\n");
    }
  }
}

static std::string generate_random_hex_16() {
  uint8_t buf[8] = {0};

#ifdef _WIN32
  NTSTATUS st = BCryptGenRandom(NULL, buf, sizeof(buf), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
  if (st != 0) {
    std::random_device rd;
    for (size_t i = 0; i < sizeof(buf); ++i) buf[i] = static_cast<uint8_t>(rd() & 0xFF);
  }
  else
#else
  std::ifstream urandom("/dev/urandom", std::ios::in | std::ios::binary);
  if (urandom) {
    urandom.read(reinterpret_cast<char*>(buf), sizeof(buf));
    if (!urandom) {
      std::random_device rd;
      for (size_t i = 0; i < sizeof(buf); ++i) buf[i] = static_cast<uint8_t>(rd() & 0xFF);
    }
  }
  else
#endif
  {
    std::random_device rd;
    for (size_t i = 0; i < sizeof(buf); ++i) buf[i] = static_cast<uint8_t>(rd() & 0xFF);
  }

  uint64_t v = 0;
  for (size_t i = 0; i < sizeof(buf); ++i) v = (v << 8) | buf[i];
  std::ostringstream oss;
  oss << std::hex << std::nouppercase << std::setw(16) << std::setfill('0') << v;
  return oss.str();
}

static void connect_callback(ws28::Client *client, ws28::HTTPRequest &req) {
  auto challenge = generate_random_hex_16();
  nlohmann::json auth = {"AUTH", challenge};
  relay_send(client, auth);

  auto up = std::make_unique<client_t>();
  up->ip = realIP(req);
  up->challenge = challenge;
  up->pubkey = "";

  client->SetUserData(up.get());
  clients_map[client] = std::move(up);

  console->debug("CONNECTED {}", clients_map[client]->ip);
}

static bool tcpcheck_callback(std::string_view /*ip*/, bool /*secure*/) {
  // console->debug("TCPCHECK {} {}", ip, secure);
  return true;
}

static bool check_callback(ws28::Client * /*client*/, ws28::HTTPRequest &req) {
  console->debug("CHECK {}", realIP(req));
  return true;
}

static void disconnect_callback(ws28::Client *client) {
  assert(client);

  console->debug("DISCONNECT {}", realIP(client));

  auto itc = clients_map.find(client);
  if (itc != clients_map.end()) {
    client->SetUserData(nullptr);
    clients_map.erase(itc);
  }

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
         method == "CLOSE" || method == "AUTH";
}

static void data_callback(ws28::Client *client, char *data, size_t len,
                          int opcode) {
  assert(client);
  assert(data);

  if (opcode != 1) {
    return;
  }

  std::string s(data, len);
  console->debug("{} >> {}", realIP(client), s);
  try {
    const auto payload = nlohmann::json::parse(s);

    if (!payload.is_array() || payload.size() < 2 || !payload[0].is_string()) {
      relay_notice(client, "error: invalid request");
      return;
    }

    std::string method = payload[0];
    if (!check_method(method)) {
      std::string id = payload[1];
      relay_notice(client, id, "error: invalid request");
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
    if (method == "AUTH") {
      do_relay_auth(client, payload);
      return;
    }
    relay_notice(client, payload[1], "error: invalid request");
  } catch (std::exception &e) {
    console->warn("!! {}", e.what());
    relay_notice(client, std::string("error: ") + e.what());
  }

#if defined(__GLIBC__) && !defined(_WIN32)
  // FIXME https://github.com/nlohmann/json/issues/1924
  malloc_trim(0);
#endif
}

static void signal_handler(uv_signal_t *req, int /*signum*/) {
  assert(req);
  uv_signal_stop(req);
  console->warn("!! SIGINT");
  for (auto &s : subscribers) {
    if (s.client == nullptr) {
      continue;
    }
    relay_notice(s.client, s.sub, "shutdown...");
    s.client->Close(0);
  }
  uv_stop(req->loop);
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
  server.SetMaxMessageSize(nip11["limitation"]["max_message_length"].get<size_t>());
  server.SetCheckConnectionCallback(check_callback);
  server.SetHTTPCallback(http_request_callback);
  server.Listen(port);
  console->info("server started :{}", port);

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
    program.add_argument("-service-url")
        .default_value(env("SERVICE_URL", ""))
        .help("service URL")
        .metavar("SERVICE_URL")
        .nargs(1);
    program.add_argument("-loglevel")
        .default_value(env("SPDLOG_LEVEL", "info"))
        .help("log level")
        .metavar("LEVEL")
        .nargs(1);
    program.add_argument("-port")
        .default_value(static_cast<short>(7447))
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

  spdlog::set_level(
      spdlog::level::from_str(program.get<std::string>("-loglevel")));
  spdlog::set_pattern("[%Y-%m-%d %H:%M:%S] [%^%l%$] %v");

  std::string prefix = "postgres://";
  auto database = program.get<std::string>("-database");
  if (!database.compare(0, prefix.size(), prefix)) {
    storage_context_init_postgresql(storage_ctx);
  } else {
    storage_context_init_sqlite3(storage_ctx);
  }

  try {
    storage_ctx.init(database);
  } catch (const std::exception &e) {
    console->error("!! Failed to initialize database: {}", e.what());
    return 1;
  }

  service_url = program.get<std::string>("-service-url");
  server(program.get<short>("-port"));

  storage_ctx.deinit();
  return 0;
}
