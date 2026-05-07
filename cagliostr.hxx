#ifndef _CAGLIOSTR_H_
#define _CAGLIOSTR_H_

#include <string>
#if defined(__GLIBC__)
#include <malloc.h>
#endif

#include <algorithm>
#include <cctype>
#include <nlohmann/json.hpp>
#include <optional>
#include <spdlog/common.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>
#include <sstream>

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
  std::vector<std::vector<std::string>> and_tags{};
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

inline bool matched_filters(const std::vector<filter_t> &filters,
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
      auto all_tags_matched = true;
      for (const auto &filter_tag : filter.tags) {
        if (filter_tag.size() < 2)
          continue;
        bool this_tag_matched = false;
        for (const auto &tag : ev.tags) {
          if (tag.size() < 2)
            continue;
          if (tag[0] != filter_tag[0])
            continue;
          for (size_t fi = 1; fi < filter_tag.size(); fi++) {
            if (tag[1] == filter_tag[fi]) {
              this_tag_matched = true;
              break;
            }
          }
          if (this_tag_matched)
            break;
        }
        if (!this_tag_matched) {
          all_tags_matched = false;
          break;
        }
      }
      if (!all_tags_matched) {
        continue;
      }
    }
    if (!filter.and_tags.empty()) {
      auto all_and_tags_matched = true;
      for (const auto &filter_tag : filter.and_tags) {
        if (filter_tag.size() < 2)
          continue;
        const auto &key = filter_tag[0];
        for (size_t fi = 1; fi < filter_tag.size(); fi++) {
          bool found_value = false;
          for (const auto &tag : ev.tags) {
            if (tag.size() >= 2 && tag[0] == key && tag[1] == filter_tag[fi]) {
              found_value = true;
              break;
            }
          }
          if (!found_value) {
            all_and_tags_matched = false;
            break;
          }
        }
        if (!all_and_tags_matched)
          break;
      }
      if (!all_and_tags_matched) {
        continue;
      }
    }
    if (!filter.search.empty() && !ev.content.empty()) {
      auto found_search = true;
      std::string content = ev.content;
      std::transform(content.begin(), content.end(), content.begin(),
                     ::tolower);
      std::istringstream iss(filter.search);
      std::string word;
      while (iss >> word) {
        std::transform(word.begin(), word.end(), word.begin(), ::tolower);
        if (content.find(word) == std::string::npos) {
          found_search = false;
          break;
        }
      }
      if (!found_search) {
        continue;
      }
    }
    found = true;
  }
  return found;
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
