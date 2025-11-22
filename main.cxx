#define INITIALIZE_LOGGER

#include "cagliostr.hxx"
#include "version.h"

#include <App.h>

#include <iomanip>
#include <memory>
#include <random>
#include <sstream>
#include <unordered_map>
#include <mutex>

#ifdef _WIN32
#include <bcrypt.h>
#include <windows.h>
#else
#include <fstream>
#include <csignal>
#endif

#include <argparse/argparse.hpp>

// Forward declaration
struct PerSocketData {
  std::string ip;
  std::string challenge;
  std::string pubkey;
};

using WebSocket = uWS::WebSocket<false, true, PerSocketData>;

using subscriber_t = struct subscriber_t {
  std::string sub;
  WebSocket *ws{};
  std::vector<filter_t> filters;
};

// global variables
static std::mutex subscribers_mutex;
static std::vector<subscriber_t> subscribers;

static std::string service_url;

static storage_context_t storage_ctx;

static auto nip11 = nlohmann::json{
    {"name", "cagliostr"},
    {"description", "Nostr relay written in C++"},
    {"pubkey",
     "2c7cc62a697ea3a7826521f3fd34f0cb273693cbe5e9310f35449f43622a5cdc"},
    {"contact", "mattn.jp@gmail.com"},
    {"supported_nips",
     nlohmann::json::array({1, 2, 4, 9, 11, 12, 15, 16, 20, 22, 26, 28, 33, 40,
                            42, 45, 50, 62, 70})},
    {"software", "https://github.com/mattn/cagliostr"},
    {"version", VERSION},
    {"limitation", nlohmann::json{{"max_message_length", 1024 * 1024 * 5},
                                  {"max_subscriptions", 20},
                                  {"max_filters", 10},
                                  {"max_limit", 500},
                                  {"max_subid_length", 100},
                                  {"max_event_tags", 100},
                                  {"max_content_length", 16384},
                                  {"min_pow_difficulty", 30},
                                  {"auth_required", false},
                                  {"payment_required", false},
                                  {"restricted_writes", false}}},
    {"fees", nlohmann::json::object()},
    {"icon",
     "https://raw.githubusercontent.com/mattn/cagliostr/main/cagliostr.png"}};

static const std::string realIP(WebSocket *ws) {
  auto *data = ws->getUserData();
  if (data && !data->ip.empty()) {
    return data->ip;
  }
  return std::string(ws->getRemoteAddressAsText());
}

static const std::string get_challenge(WebSocket *ws) {
  auto *data = ws->getUserData();
  if (data) {
    return data->challenge;
  }
  return "";
}

static void set_auth_pubkey(WebSocket *ws, const std::string &pubkey) {
  auto *data = ws->getUserData();
  if (data) {
    data->pubkey = pubkey;
  }
}

static bool check_auth_pubkey(WebSocket *ws, const std::string &pubkey) {
  auto *data = ws->getUserData();
  if (data) {
    return data->pubkey == pubkey;
  }
  return false;
}

static void relay_send(WebSocket *ws, const nlohmann::json &data) {
  const auto &s = data.dump();
  console->debug("{} << {}", realIP(ws), s);
  ws->send(s, uWS::OpCode::TEXT);
}

static inline void relay_notice(WebSocket *ws, const std::string &msg) {
  nlohmann::json data = {"NOTICE", msg};
  relay_send(ws, data);
}

static inline void relay_notice(WebSocket *ws, const std::string &id,
                                const std::string &msg) {
  nlohmann::json data = {"NOTICE", id, msg};
  relay_send(ws, data);
}

static inline void relay_closed(WebSocket *ws, const std::string &msg) {
  nlohmann::json data = {"CLOSED", msg};
  relay_send(ws, data);
  ws->close();
}

static inline void relay_closed(WebSocket *ws, const std::string &id,
                                const std::string &msg) {
  nlohmann::json data = {"CLOSED", id, msg};
  relay_send(ws, data);
}

static inline std::string to_lower(std::string s) {
  std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
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
      if (idstr.size() > 64 || idstr.empty()) {
        console->warn("make_filter: ids element invalid length: {}", idstr);
        return false;
      }
      if (idstr.size() == 64 && !is_hex(idstr, 64)) {
        console->warn("make_filter: ids element invalid hex: {}", idstr);
        return false;
      }
      for (const auto &c : idstr) {
        if (!std::isxdigit(static_cast<unsigned char>(c))) {
          console->warn("make_filter: ids element invalid hex: {}", idstr);
          return false;
        }
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
      if (authorstr.size() > 64 || authorstr.empty()) {
        console->warn("make_filter: authors element invalid length: {}",
                      authorstr);
        return false;
      }
      if (authorstr.size() == 64 && !is_hex(authorstr, 64)) {
        console->warn("make_filter: authors element invalid hex: {}",
                      authorstr);
        return false;
      }
      for (const auto &c : authorstr) {
        if (!std::isxdigit(static_cast<unsigned char>(c))) {
          console->warn("make_filter: authors element invalid hex: {}",
                        authorstr);
          return false;
        }
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
          console->warn("make_filter: tag {} elements must be string",
                        it.key());
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
    auto limit_val = data["limit"].get<int>();
    int max_limit = nip11["limitation"]["max_limit"];
    if (limit_val < 0) {
      console->warn("make_filter: limit out of range: {}", limit_val);
      return false;
    }
    if (limit_val > max_limit) {
      console->warn("make_filter: limit out of range: {}", limit_val);
      limit_val = max_limit;
    }
    filter.limit = limit_val;
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

static void do_relay_req(WebSocket *ws, const nlohmann::json &data) {
  std::string sub = data[1];

  // Check subscription limits
  int sub_count = 0;
  for (const auto &s : subscribers) {
    if (s.ws == ws) {
      sub_count++;
    }
  }
  int max_subs = nip11["limitation"]["max_subscriptions"];
  if (sub_count >= max_subs) {
    relay_notice(ws, sub, "error: too many subscriptions");
    return;
  }

  std::vector<filter_t> filters;
  int max_filters = nip11["limitation"]["max_filters"];
  for (size_t i = 2; i < data.size(); i++) {
    if (!data[i].is_object()) {
      continue;
    }
    if (filters.size() >= static_cast<size_t>(max_filters)) {
      relay_notice(ws, sub, "error: too many filters");
      return;
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
    relay_send(ws, reply);
    return;
  }

  // Remove existing subscription with same ID
  auto it = subscribers.begin();
  while (it != subscribers.end()) {
    if (it->sub == sub && it->ws == ws) {
      it = subscribers.erase(it);
    } else {
      it++;
    }
  }

  subscribers.push_back(subscriber_t{sub, ws, filters});

  storage_ctx.send_records(
      [&](const nlohmann::json &_data) { relay_send(ws, _data); }, sub,
      filters, false);
  const auto reply = nlohmann::json::array({"EOSE", sub});
  relay_send(ws, reply);
}

static void do_relay_count(WebSocket *ws, const nlohmann::json &data) {
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
    relay_send(ws, reply);
    return;
  }

  storage_ctx.send_records(
      [&](const nlohmann::json &_data) { relay_send(ws, _data); }, sub,
      filters, true);
}

static void do_relay_close(WebSocket *ws, const nlohmann::json &data) {
  std::string sub = data[1];
  auto it = subscribers.begin();
  while (it != subscribers.end()) {
    if (it->sub == sub && it->ws == ws) {
      it = subscribers.erase(it);
    } else {
      it++;
    }
  }
  nlohmann::json reply = {"CLOSED", sub, ""};
  relay_send(ws, reply);
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

static void do_relay_event(WebSocket *ws, const nlohmann::json &data) {
  try {
    const event_t ev = data[1];

    // Validate event size limits
    int max_tags = nip11["limitation"]["max_event_tags"];
    int max_content = nip11["limitation"]["max_content_length"];
    if (ev.tags.size() > static_cast<size_t>(max_tags)) {
      relay_notice(ws, ev.id, "error: too many tags");
      return;
    }
    if (ev.content.size() > static_cast<size_t>(max_content)) {
      relay_notice(ws, ev.id, "error: content too large");
      return;
    }

    if (!check_event(ev)) {
      relay_notice(ws, ev.id, "error: invalid id or signature");
      return;
    }

    for (const auto &tag : ev.tags) {
      if (tag.size() == 1 && tag[0] == "-") {
        if (!check_auth_pubkey(ws, ev.pubkey)) {
          const auto reply = nlohmann::json::array(
              {"OK", ev.id, false, "auth-required: authentication required"});
          relay_send(ws, reply);
          return;
        }
      }
    }

    if (ev.kind == 5) {
      for (const auto &tag : ev.tags) {
        if (tag.size() >= 2 && tag[0] == "e") {
          for (size_t i = 1; i < tag.size(); i++) {
            if (storage_ctx.delete_record_by_id(tag[i]) < 0) {
              relay_notice(ws, ev.id, "error: failed to delete event");
              return;
            }
          }
        }
      }
      nlohmann::json reply = {"OK", ev.id, true, ""};
      relay_send(ws, reply);
      return;
    } else if (ev.kind == 62) {
      // NIP-62: Request to Vanish
      // First, check if we should delete events for this relay
      bool should_process = false;
      for (const auto &tag : ev.tags) {
        if (tag.size() >= 2 && tag[0] == "relay") {
          if (tag[1] == "ALL_RELAYS" || tag[1] == service_url) {
            should_process = true;
            break;
          }
          // Check if the relay URL matches (with or without trailing slash)
          std::string relay_url = tag[1];
          std::string service_url_copy = service_url;
          while (!relay_url.empty() && relay_url.back() == '/') {
            relay_url.pop_back();
          }
          while (!service_url_copy.empty() && service_url_copy.back() == '/') {
            service_url_copy.pop_back();
          }
          if (relay_url == service_url_copy) {
            should_process = true;
            break;
          }
        }
      }

      if (should_process) {
        // Delete all events from the pubkey (except kind 62 itself for
        // propagation)
        if (storage_ctx.delete_all_events_by_pubkey(ev.pubkey, ev.created_at) <
            0) {
          relay_notice(ws, ev.id, "error: failed to vanish events");
          return;
        }
      }

      // Always store kind 62 event for propagation to other relays
      if (!storage_ctx.insert_record(ev)) {
        relay_notice(ws, ev.id, "error: duplicate event");
        return;
      }

      for (const auto &s : subscribers) {
        if (matched_filters(s.filters, ev)) {
          nlohmann::json reply = {"EVENT", s.sub, ev};
          relay_send(s.ws, reply);
        }
      }
      nlohmann::json reply = {"OK", ev.id, true, ""};
      relay_send(ws, reply);
      return;
    } else {
      if (20000 <= ev.kind && ev.kind < 30000) {
        relay_notice(ws, ev.id, "error: ephemeral events not stored");
        return;
      } else if (ev.kind == 0 || ev.kind == 3 ||
                 (10000 <= ev.kind && ev.kind < 20000)) {
        if (storage_ctx.delete_record_by_kind_and_pubkey(ev.kind, ev.pubkey,
                                                         ev.created_at) < 0) {
          relay_notice(ws, ev.id, "error: failed to replace event");
          return;
        }
      } else if (30000 <= ev.kind && ev.kind < 40000) {
        std::string d;
        for (const auto &tag : ev.tags) {
          if (tag.size() >= 2 && tag[0] == "d") {
            if (storage_ctx.delete_record_by_kind_and_pubkey_and_dtag(
                    ev.kind, ev.pubkey, tag, ev.created_at) < 0) {
              relay_notice(ws, ev.id, "error: failed to replace event");
              return;
            }
          }
        }
      }

      if (!storage_ctx.insert_record(ev)) {
        relay_notice(ws, ev.id, "error: duplicate event");
        return;
      }
    }

    for (const auto &s : subscribers) {
      if (matched_filters(s.filters, ev)) {
        nlohmann::json reply = {"EVENT", s.sub, ev};
        relay_send(s.ws, reply);
      }
    }
    nlohmann::json reply = {"OK", ev.id, true, ""};
    relay_send(ws, reply);
  } catch (std::exception &e) {
    console->warn("!! {}", e.what());
  }
}

static void do_relay_auth(WebSocket *ws, const nlohmann::json &data) {
  try {
    const event_t ev = data[1];
    if (!check_event(ev)) {
      relay_notice(ws, "error: invalid id or signature");
      return;
    }

    auto cc = get_challenge(ws);
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
      set_auth_pubkey(ws, ev.pubkey);
      nlohmann::json reply = {"OK", ev.id, true, ""};
      relay_send(ws, reply);
      return;
    }

    nlohmann::json reply = {"OK", ev.id, false,
                            "error: failed to authenticate"};
    relay_send(ws, reply);
  } catch (std::exception &e) {
    console->warn("!! {}", e.what());
  }
}

static auto html = R"(<!DOCTYPE html>
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
</html>)";

static std::string generate_random_hex_16() {
  uint8_t buf[8] = {0};

#ifdef _WIN32
  NTSTATUS st =
      BCryptGenRandom(NULL, buf, sizeof(buf), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
  if (st != 0) {
    std::random_device rd;
    for (size_t i = 0; i < sizeof(buf); ++i)
      buf[i] = static_cast<uint8_t>(rd() & 0xFF);
  } else
#else
  std::ifstream urandom("/dev/urandom", std::ios::in | std::ios::binary);
  if (urandom) {
    urandom.read(reinterpret_cast<char *>(buf), sizeof(buf));
    if (!urandom) {
      std::random_device rd;
      for (size_t i = 0; i < sizeof(buf); ++i)
        buf[i] = static_cast<uint8_t>(rd() & 0xFF);
    }
  } else
#endif
  {
    std::random_device rd;
    for (size_t i = 0; i < sizeof(buf); ++i)
      buf[i] = static_cast<uint8_t>(rd() & 0xFF);
  }

  uint64_t v = 0;
  for (size_t i = 0; i < sizeof(buf); ++i)
    v = (v << 8) | buf[i];
  std::ostringstream oss;
  oss << std::hex << std::nouppercase << std::setw(16) << std::setfill('0')
      << v;
  return oss.str();
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

static uWS::App *global_app = nullptr;

static void signal_handler(int /*signum*/) {
  console->warn("!! SIGINT");
  std::lock_guard<std::mutex> lock(subscribers_mutex);
  for (auto &s : subscribers) {
    if (s.ws == nullptr) {
      continue;
    }
    relay_notice(s.ws, s.sub, "shutdown...");
  }
  if (global_app) {
    global_app->close();
  }
}

static void server(short port) {
  uWS::App app;
  global_app = &app;

  app.ws<PerSocketData>("/*", {
    /* Settings */
    .compression = uWS::DISABLED,
    .maxPayloadLength = static_cast<unsigned int>(nip11["limitation"]["max_message_length"].get<size_t>()),
    .idleTimeout = 120,
    .maxBackpressure = 1024 * 1024,
    .closeOnBackpressureLimit = false,
    .resetIdleTimeoutOnSend = true,
    .sendPingsAutomatically = true,
    
    /* Handlers */
    .upgrade = nullptr,
    .open = [](WebSocket *ws) {
      auto *data = ws->getUserData();
      data->ip = std::string(ws->getRemoteAddressAsText());
      data->challenge = generate_random_hex_16();
      data->pubkey = "";
      
      nlohmann::json auth = {"AUTH", data->challenge};
      relay_send(ws, auth);
      
      console->debug("CONNECTED {}", data->ip);
    },
    .message = [](WebSocket *ws, std::string_view message, uWS::OpCode opcode) {
      if (opcode != uWS::OpCode::TEXT) {
        return;
      }
      
      std::string s(message);
      console->debug("{} >> {}", realIP(ws), s);
      
      try {
        const auto payload = nlohmann::json::parse(s);

        if (!payload.is_array() || payload.size() < 2 || !payload[0].is_string()) {
          relay_notice(ws, "error: invalid request");
          return;
        }

        std::string method = payload[0];
        if (method != "EVENT" && method != "REQ" && method != "COUNT" &&
            method != "CLOSE" && method != "AUTH") {
          if (payload.size() >= 2 && payload[1].is_string()) {
            std::string id = payload[1];
            relay_notice(ws, id, "error: invalid request");
          } else {
            relay_notice(ws, "error: invalid request");
          }
          return;
        }

        // Validate subscription ID length
        if ((method == "REQ" || method == "COUNT" || method == "CLOSE") &&
            payload[1].is_string()) {
          auto sub_id = payload[1].get<std::string>();
          int max_subid = nip11["limitation"]["max_subid_length"];
          if (sub_id.size() > static_cast<size_t>(max_subid)) {
            relay_notice(ws, "error: subscription id too long");
            return;
          }
        }

        if (method == "REQ") {
          if (payload.size() < 3) {
            relay_notice(ws, payload[1], "error: invalid request");
            return;
          }
          do_relay_req(ws, payload);
        } else if (method == "COUNT") {
          if (payload.size() < 3) {
            relay_notice(ws, payload[1], "error: invalid request");
            return;
          }
          do_relay_count(ws, payload);
        } else if (method == "CLOSE") {
          do_relay_close(ws, payload);
        } else if (method == "EVENT") {
          do_relay_event(ws, payload);
        } else if (method == "AUTH") {
          do_relay_auth(ws, payload);
        } else {
          relay_notice(ws, payload[1], "error: invalid request");
        }
      } catch (std::exception &e) {
        console->warn("!! {}", e.what());
        relay_notice(ws, std::string("error: ") + e.what());
      }

#if defined(__GLIBC__) && !defined(_WIN32)
      malloc_trim(0);
#endif
    },
    .drain = [](WebSocket */*ws*/) {
      /* Check getBufferedAmount here */
    },
    .ping = [](WebSocket */*ws*/, std::string_view) {
    },
    .pong = [](WebSocket */*ws*/, std::string_view) {
    },
    .close = [](WebSocket *ws, int /*code*/, std::string_view /*message*/) {
      console->debug("DISCONNECT {}", realIP(ws));
      
      std::lock_guard<std::mutex> lock(subscribers_mutex);
      auto it = subscribers.begin();
      while (it != subscribers.end()) {
        if (it->ws == ws) {
          it = subscribers.erase(it);
        } else {
          it++;
        }
      }
    }
  }).get("/.well-known/nostr.json", [](auto *res, auto *req) {
    std::string name = std::string(req->getQuery("name"));
    if (!service_url.empty() && !name.empty()) {
      auto pos = service_url.find("://");
      if (pos != std::string::npos) {
        std::string relay = service_url.substr(0, pos) == "https" ? 
                           "wss" + service_url.substr(pos) : 
                           "ws" + service_url.substr(pos);
        nlohmann::json nip05 = {
          {"names", {{name, nip11["pubkey"]}}},
          {"relays", {{nip11["pubkey"], {relay}}}}
        };
        res->writeHeader("Content-Type", "application/json");
        res->end(nip05.dump());
        return;
      }
    }
    res->writeStatus("404 Not Found");
    res->end("Not Found");
  }).get("/", [](auto *res, auto *req) {
    // Check Accept header
    std::string accept;
    for (auto header : *req) {
      if (header.first == "accept") {
        accept = std::string(header.second);
        break;
      }
    }
    
    if (accept.find("application/nostr+json") != std::string::npos) {
      res->writeHeader("Content-Type", "application/nostr+json");
      res->end(nip11.dump());
    } else {
      res->writeHeader("Content-Type", "text/html; charset=UTF-8");
      res->end(html);
    }
  }).listen(port, [port](auto *listen_socket) {
    if (listen_socket) {
      console->info("server started :{}", port);
    } else {
      console->error("Failed to listen on port {}", port);
    }
  }).run();
  
  global_app = nullptr;
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
  
  // Setup signal handler
  std::signal(SIGINT, signal_handler);
  
  server(program.get<short>("-port"));

  storage_ctx.deinit();
  return 0;
}
