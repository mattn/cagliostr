#ifndef _CAGLIOSTR_H_
#define _CAGLIOSTR_H_

#include <string>
#if defined(__GLIBC__)
#include <malloc.h>
#endif

#include <ctime>
#include <list>
#include <unordered_map>

#include <nlohmann/json.hpp>
#include <optional>
#include <spdlog/common.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

using event_t = struct event_t {
  std::string id;
  std::string pubkey;
  std::time_t created_at;
  int kind;
  std::vector<std::vector<std::string>> tags;
  std::string content;
  std::string sig;
};

using filter_t = struct filter_t {
  std::vector<std::string> ids{};
  std::vector<std::string> authors{};
  std::vector<int> kinds{};
  std::vector<std::vector<std::string>> tags{};
  std::time_t since{};
  std::time_t until{};
  int limit{500};
  std::string search;
};

using storage_context_t = struct storage_context_t {
  void (*init)(const std::string &);
  void (*deinit)();
  std::optional<event_t> (*get_event_by_id)(const std::string &);
  bool (*insert_record)(const event_t &);
  int (*delete_record_by_id_and_pubkey)(const std::string &,
                                        const std::string &);
  int (*delete_record_by_kind_and_pubkey)(int, const std::string &,
                                          std::time_t);
  int (*delete_record_by_kind_and_pubkey_and_dtag)(
      int, const std::string &, const std::vector<std::string> &, std::time_t);
  int (*delete_record_by_id_and_kind_and_ptag)(
      const std::string &, int, const std::vector<std::string> &);
  int (*delete_all_events_by_pubkey)(const std::string &, std::time_t);
  bool (*send_records)(std::function<void(const nlohmann::json &)>,
                       const std::string &, const std::vector<filter_t> &, bool,
                       bool *);
};

void storage_context_init_sqlite3(storage_context_t &);
void storage_context_init_postgresql(storage_context_t &);

bool check_event(const event_t &);

// NIP-13: count the number of leading zero bits in a hex-encoded event id.
int count_leading_zero_bits(const std::string &);

inline void to_json(nlohmann::json &j, const event_t &e) {
  j = nlohmann::json{
      {"id", e.id},           {"pubkey", e.pubkey},
      {"content", e.content}, {"created_at", e.created_at},
      {"kind", e.kind},       {"tags", e.tags},
      {"sig", e.sig},
  };
}

inline void from_json(const nlohmann::json &j, event_t &e) {
  j.at("id").get_to(e.id);
  j.at("pubkey").get_to(e.pubkey);
  j.at("content").get_to(e.content);
  j.at("created_at").get_to(e.created_at);
  j.at("kind").get_to(e.kind);
  j.at("tags").get_to(e.tags);
  j.at("sig").get_to(e.sig);
}

// NIP-09: parse an addressable event coordinate ("kind:pubkey:dtag") from an
// "a" tag value. Returns false when the value is malformed.
inline bool parse_a_coordinate(const std::string &coordinate, int &kind,
                               std::string &pubkey, std::string &dtag) {
  auto first = coordinate.find(':');
  if (first == std::string::npos) {
    return false;
  }
  auto second = coordinate.find(':', first + 1);
  if (second == std::string::npos) {
    return false;
  }
  const auto kind_str = coordinate.substr(0, first);
  if (kind_str.empty()) {
    return false;
  }
  try {
    size_t pos = 0;
    kind = std::stoi(kind_str, &pos);
    if (pos != kind_str.size()) {
      return false;
    }
  } catch (const std::exception &) {
    return false;
  }
  pubkey = coordinate.substr(first + 1, second - first - 1);
  dtag = coordinate.substr(second + 1);
  if (pubkey.empty()) {
    return false;
  }
  return true;
}

// NIP-22: report whether created_at falls within the accepted window relative
// to the current time. A limit of 0 disables that side of the check.
inline bool created_at_within_limits(std::time_t created_at, std::time_t now,
                                     std::time_t lower_limit,
                                     std::time_t upper_limit) {
  if (lower_limit > 0 && created_at < now - lower_limit) {
    return false;
  }
  if (upper_limit > 0 && created_at > now + upper_limit) {
    return false;
  }
  return true;
}

// Fixed-window rate limiter keyed by an arbitrary string (an IP address or a
// pubkey). State is held in an LRU cache bounded by max_keys so that a flood of
// unique keys cannot grow memory without limit; the least-recently-used key,
// whose window is also the most stale, is evicted first. A limit or window of 0
// disables the limiter and allows everything.
class rate_limiter_t {
public:
  void configure(int limit, std::time_t window,
                 std::size_t max_keys = 100000) {
    limit_ = limit;
    window_ = window;
    max_keys_ = max_keys;
  }

  bool enabled() const { return limit_ > 0 && window_ > 0; }

  // Record a hit for the given key at time `now` and report whether it is
  // within the limit. When disabled, everything is allowed.
  bool allow(const std::string &key, std::time_t now) {
    if (!enabled()) {
      return true;
    }
    auto it = entries_.find(key);
    if (it == entries_.end()) {
      if (max_keys_ > 0 && entries_.size() >= max_keys_) {
        entries_.erase(lru_.back());
        lru_.pop_back();
      }
      lru_.push_front(key);
      it = entries_.emplace(key, entry_t{lru_.begin(), now, 0}).first;
    } else {
      // Touch: move this key to the most-recently-used end.
      lru_.splice(lru_.begin(), lru_, it->second.pos);
    }
    auto &e = it->second;
    if (now - e.start >= window_) {
      e.start = now;
      e.count = 0;
    }
    e.count++;
    return e.count <= limit_;
  }

  std::size_t size() const { return entries_.size(); }

private:
  struct entry_t {
    std::list<std::string>::iterator pos;
    std::time_t start;
    int count;
  };

  int limit_{0};
  std::time_t window_{0};
  std::size_t max_keys_{0};
  std::list<std::string> lru_;
  std::unordered_map<std::string, entry_t> entries_;
};

inline std::string escape_like(const std::string &data) {
  std::string result;
  for (const auto c : data) {
    if (c == '_' || c == '%' || c == '\\')
      result.push_back('\\');
    result.push_back((char)c);
  }
  return result;
}

#ifdef INITIALIZE_LOGGER
auto console = spdlog::stdout_color_mt("cagliostr");
#else
extern std::shared_ptr<spdlog::logger> console;
#endif

#endif
