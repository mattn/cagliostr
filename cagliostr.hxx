#ifndef _CAGLIOSTR_H_
#define _CAGLIOSTR_H_

#include <string>
#if defined(__GLIBC__)
#include <malloc.h>
#endif

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
                       const std::string &, const std::vector<filter_t> &,
                       bool);
};

void storage_context_init_sqlite3(storage_context_t &);
void storage_context_init_postgresql(storage_context_t &);

bool check_event(const event_t &);

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
