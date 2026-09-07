#include "cagliostr.hxx"
#include <charconv>
#include <ctime>
#include <iostream>
#include <sstream>
#include <unordered_set>

#include <sqlite3.h>

// global variables
static sqlite3 *conn = nullptr;

#define PARAM_TYPE_NUMBER (0)
#define PARAM_TYPE_STRING (1)

using param_t = struct param_t {
  int t{};
  int n{};
  std::string s{};
};

static std::string join(const std::vector<std::string> &v,
                        const char *delim = 0) {
  std::string s;
  if (!v.empty()) {
    s += v[0];
    for (decltype(v.size()) i = 1, c = v.size(); i < c; ++i) {
      if (delim) {
        s += delim;
      }
      s += v[i];
    }
  }
  return s;
}

static std::optional<event_t> get_event_by_id(const std::string &id) {
  std::string sql =
      R"(SELECT id, pubkey, created_at, kind, tags, content, sig FROM event WHERE id = ?)";

  sqlite3_stmt *stmt = nullptr;
  auto ret =
      sqlite3_prepare_v2(conn, sql.data(), (int)sql.size(), &stmt, nullptr);
  if (ret != SQLITE_OK) {
    console->error("{}", sqlite3_errmsg(conn));
    return std::nullopt;
  }

  sqlite3_bind_text(stmt, 1, id.data(), (int)id.size(), SQLITE_TRANSIENT);
  ret = sqlite3_step(stmt);
  if (ret != SQLITE_ROW) {
    if (ret != SQLITE_DONE) {
      console->error("{}", sqlite3_errmsg(conn));
    }
    sqlite3_finalize(stmt);
    return std::nullopt;
  }

  nlohmann::json ej;
  ej["id"] = (char *)sqlite3_column_text(stmt, 0);
  ej["pubkey"] = (char *)sqlite3_column_text(stmt, 1);
  ej["created_at"] = sqlite3_column_int64(stmt, 2);
  ej["kind"] = sqlite3_column_int(stmt, 3);
  const unsigned char *j = sqlite3_column_text(stmt, 4);
  ej["tags"] = nlohmann::json::parse(j);
  ej["content"] = std::string(reinterpret_cast<const char *>(sqlite3_column_text(stmt, 5)),
                                    sqlite3_column_bytes(stmt, 5));
  ej["sig"] = (char *)sqlite3_column_text(stmt, 6);
  sqlite3_finalize(stmt);
  return ej;
}

static bool insert_record(const event_t &ev) {
  const auto sql =
      R"(INSERT INTO event (id, pubkey, created_at, kind, tags, content, sig) VALUES (?, ?, ?, ?, ?, ?, ?))";
  sqlite3_stmt *stmt = nullptr;
  auto ret = sqlite3_prepare_v2(conn, sql, -1, &stmt, nullptr);
  if (ret != SQLITE_OK) {
    console->error("{}", sqlite3_errmsg(conn));
    return false;
  }
  nlohmann::json tags = ev.tags;
  auto s = tags.dump();
  sqlite3_bind_text(stmt, 1, ev.id.data(), (int)ev.id.size(), SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 2, ev.pubkey.data(), (int)ev.pubkey.size(),
                    SQLITE_TRANSIENT);
  sqlite3_bind_int64(stmt, 3, ev.created_at);
  sqlite3_bind_int(stmt, 4, ev.kind);
  sqlite3_bind_text(stmt, 5, s.data(), (int)s.size(), SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 6, ev.content.data(), (int)ev.content.size(),
                    SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 7, ev.sig.data(), (int)ev.sig.size(),
                    SQLITE_TRANSIENT);

  ret = sqlite3_step(stmt);
  if (ret != SQLITE_DONE) {
    console->error("{}", sqlite3_errmsg(conn));
    sqlite3_finalize(stmt);
    return false;
  }
  sqlite3_finalize(stmt);

  return true;
}

static bool send_records(std::function<void(const nlohmann::json &)> sender,
                         const std::string &sub,
                         const std::vector<filter_t> &filters, bool do_count,
                         bool *has_more) {
  int64_t count = 0;
  std::unordered_set<std::string> sent_ids;
  std::vector<std::string> count_conditions;
  std::vector<param_t> params;
  if (has_more != nullptr) {
    *has_more = false;
  }
  for (const auto &filter : filters) {
    std::string sql;
    if (do_count) {
      sql = R"(SELECT COUNT(id) FROM event)";
    } else {
      sql =
          R"(SELECT id, pubkey, created_at, kind, tags, content, sig FROM event)";
    }

    auto limit = 500;
    if (!do_count) {
      params.clear();
    }
    std::vector<std::string> conditions;
    if (!filter.ids.empty()) {
      if (filter.ids.size() == 1) {
        conditions.push_back("id = ?");
        params.push_back({.t = PARAM_TYPE_STRING, .s = filter.ids.front()});
      } else {
        std::string condition;
        for (const auto &id : filter.ids) {
          condition += "?,";
          params.push_back({.t = PARAM_TYPE_STRING, .s = id});
        }
        condition.pop_back();
        conditions.push_back("id in (" + condition + ")");
      }
    }
    if (!filter.authors.empty()) {
      if (filter.authors.size() == 1) {
        conditions.push_back("pubkey = ?");
        params.push_back({.t = PARAM_TYPE_STRING, .s = filter.authors.front()});
      } else {
        std::string condition;
        for (const auto &author : filter.authors) {
          condition += "?,";
          params.push_back({.t = PARAM_TYPE_STRING, .s = author});
        }
        condition.pop_back();
        conditions.push_back("pubkey in (" + condition + ")");
      }
    }
    if (!filter.kinds.empty()) {
      if (filter.kinds.size() == 1) {
        conditions.push_back("kind = ?");
        params.push_back({.t = PARAM_TYPE_NUMBER, .n = filter.kinds.front()});
      } else {
        std::string condition;
        for (const auto &kind : filter.kinds) {
          condition += "?,";
          params.push_back({.t = PARAM_TYPE_NUMBER, .n = kind});
        }
        condition.pop_back();
        conditions.push_back("kind in (" + condition + ")");
      }
    }
    for (const auto &tag : filter.tags) {
      if (tag.size() < 2) {
        continue;
      }
      params.push_back({.t = PARAM_TYPE_STRING, .s = tag[0]});
      std::vector<std::string> values;
      for (size_t i = 1; i < tag.size(); ++i) {
        values.push_back("?");
        params.push_back({.t = PARAM_TYPE_STRING, .s = tag[i]});
      }
      conditions.push_back(
          "EXISTS (SELECT 1 FROM json_each(event.tags) AS tag "
          "WHERE json_extract(tag.value, '$[0]') = ? "
          "AND json_extract(tag.value, '$[1]') IN (" + join(values, ",") + "))");
    }
    if (filter.since.has_value()) {
      std::ostringstream os;
      os << *filter.since;
      conditions.push_back("created_at >= " + os.str());
    }
    if (filter.until.has_value()) {
      std::ostringstream os;
      os << *filter.until;
      conditions.push_back("created_at <= " + os.str());
    }
    if (filter.limit >= 0 && filter.limit < limit) {
      limit = filter.limit;
    }
    if (!filter.search.empty()) {
      std::istringstream iss(filter.search);
      std::string term;
      while (iss >> term) {
        params.push_back({.t = PARAM_TYPE_STRING,
                          .s = "%" + escape_like(term) + "%"});
        conditions.push_back(R"(content LIKE ? ESCAPE '\')");
      }
    }
    if (do_count) {
      count_conditions.push_back(conditions.empty() ? "1=1" : join(conditions, " AND "));
      if (count_conditions.size() != filters.size()) {
        continue;
      }
      sql = "SELECT COUNT(*) FROM event WHERE (" + join(count_conditions, ") OR (") + ")";
    } else if (!conditions.empty()) {
      sql += " WHERE " + join(conditions, " AND ");
    }
    if (!do_count) {
      sql += " ORDER BY created_at DESC, id ASC LIMIT ?";
    }

    sqlite3_stmt *stmt = nullptr;
    auto ret =
        sqlite3_prepare_v2(conn, sql.data(), (int)sql.size(), &stmt, nullptr);
    if (ret != SQLITE_OK) {
      console->error("{}", sqlite3_errmsg(conn));
      return false;
    }

    for (decltype(params.size()) i = 0; i < params.size(); i++) {
      switch (params.at(i).t) {
      case PARAM_TYPE_NUMBER:
        sqlite3_bind_int(stmt, i + 1, params.at(i).n);
        break;
      case PARAM_TYPE_STRING:
        sqlite3_bind_text(stmt, i + 1, params.at(i).s.data(),
                          (int)params.at(i).s.size(), SQLITE_TRANSIENT);
        break;
      }
    }

    if (!do_count) {
      // Fetch one extra row so we can tell whether more matching events exist
      // beyond the requested limit (NIP-67 EOSE completeness hint).
      sqlite3_bind_int(stmt, params.size() + 1, limit + 1);
    }
    if (do_count) {
      ret = sqlite3_step(stmt);
      if (ret != SQLITE_ROW) {
        console->error("{}", sqlite3_errmsg(conn));
        sqlite3_finalize(stmt);
        return false;
      }
      count += sqlite3_column_int64(stmt, 0);
      sqlite3_finalize(stmt);
    } else {
      auto fetched = 0;
      while (true) {
        ret = sqlite3_step(stmt);
        if (ret == SQLITE_DONE) {
          break;
        }
        if (ret != SQLITE_ROW) {
          console->error("{}", sqlite3_errmsg(conn));
          sqlite3_finalize(stmt);
          return false;
        }
        if (++fetched > limit) {
          // The extra row proves more matching events remain on the relay.
          if (has_more != nullptr) {
            *has_more = true;
          }
          break;
        }
        nlohmann::json ej;
        ej["id"] = (char *)sqlite3_column_text(stmt, 0);
        ej["pubkey"] = (char *)sqlite3_column_text(stmt, 1);
        ej["created_at"] = sqlite3_column_int64(stmt, 2);
        ej["kind"] = sqlite3_column_int(stmt, 3);
        const unsigned char *j = sqlite3_column_text(stmt, 4);
        ej["tags"] = nlohmann::json::parse(j);
        ej["content"] = std::string(reinterpret_cast<const char *>(sqlite3_column_text(stmt, 5)),
                                    sqlite3_column_bytes(stmt, 5));
        ej["sig"] = (char *)sqlite3_column_text(stmt, 6);

        if (ej["tags"].is_array() && ej["tags"].size() > 0) {
          std::vector<std::vector<std::string>> tags;
          ej["tags"].get_to(tags);
          if (has_expired_tags(tags, std::time(nullptr))) {
            continue;
          }
        }

        nlohmann::json reply = {"EVENT", sub, ej};
        if (sent_ids.insert(ej["id"].get<std::string>()).second) {
          sender(reply);
        }
      }
      sqlite3_finalize(stmt);
    }
  }

  if (do_count) {
    nlohmann::json cc;
    cc["count"] = count;
    nlohmann::json reply = {"COUNT", sub, cc};
    sender(reply);
  }
  return true;
}

static int delete_record_by_id_and_pubkey(const std::string &id,
                                          const std::string &pubkey) {
  const auto sql = R"(DELETE FROM event WHERE id = ? AND pubkey = ?)";
  sqlite3_stmt *stmt = nullptr;
  auto ret = sqlite3_prepare_v2(conn, sql, (int)strlen(sql), &stmt, nullptr);
  if (ret != SQLITE_OK) {
    console->error("{}", sqlite3_errmsg(conn));
    return -1;
  }
  sqlite3_bind_text(stmt, 1, id.data(), (int)id.size(), SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 2, pubkey.data(), (int)pubkey.size(),
                    SQLITE_TRANSIENT);

  ret = sqlite3_step(stmt);
  if (ret != SQLITE_DONE) {
    console->error("{}", sqlite3_errmsg(conn));
    sqlite3_finalize(stmt);
    return -1;
  }
  sqlite3_finalize(stmt);

  return sqlite3_changes(conn);
}

static int delete_record_by_kind_and_pubkey(int kind, const std::string &pubkey,
                                            std::time_t created_at) {
  const auto sql =
      R"(DELETE FROM event WHERE kind = ? AND pubkey = ? AND created_at < ?)";
  sqlite3_stmt *stmt = nullptr;
  auto ret = sqlite3_prepare_v2(conn, sql, (int)strlen(sql), &stmt, nullptr);
  if (ret != SQLITE_OK) {
    console->error("{}", sqlite3_errmsg(conn));
    return -1;
  }
  sqlite3_bind_int(stmt, 1, kind);
  sqlite3_bind_text(stmt, 2, pubkey.data(), (int)pubkey.size(),
                    SQLITE_TRANSIENT);
  sqlite3_bind_int64(stmt, 3, created_at);

  ret = sqlite3_step(stmt);
  if (ret != SQLITE_DONE) {
    console->error("{}", sqlite3_errmsg(conn));
    sqlite3_finalize(stmt);
    return -1;
  }
  sqlite3_finalize(stmt);

  return sqlite3_changes(conn);
}

static int delete_record_by_kind_and_pubkey_and_dtag(
    int kind, const std::string &pubkey,
    const std::vector<std::string> &tag, std::time_t created_at) {
  if (tag.size() < 2) {
    return 0;
  }
  const auto sql =
      R"(DELETE FROM event WHERE kind = ? AND pubkey = ? AND created_at < ?
         AND EXISTS (SELECT 1 FROM json_each(event.tags) AS tag
                     WHERE json_extract(tag.value, '$[0]') = ?
                       AND json_extract(tag.value, '$[1]') = ?))";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(conn, sql, -1, &stmt, nullptr) != SQLITE_OK) {
    console->error("{}", sqlite3_errmsg(conn));
    return -1;
  }
  sqlite3_bind_int(stmt, 1, kind);
  sqlite3_bind_text(stmt, 2, pubkey.data(), (int)pubkey.size(), SQLITE_TRANSIENT);
  sqlite3_bind_int64(stmt, 3, created_at);
  sqlite3_bind_text(stmt, 4, tag[0].data(), (int)tag[0].size(), SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 5, tag[1].data(), (int)tag[1].size(), SQLITE_TRANSIENT);
  auto ret = sqlite3_step(stmt);
  if (ret != SQLITE_DONE) {
    console->error("{}", sqlite3_errmsg(conn));
    sqlite3_finalize(stmt);
    return -1;
  }
  sqlite3_finalize(stmt);
  return sqlite3_changes(conn);
}

static int delete_record_by_id_and_kind_and_ptag(
    const std::string &id, int kind, const std::vector<std::string> &tag) {
  if (tag.size() < 2) {
    return 0;
  }
  const auto sql =
      R"(DELETE FROM event WHERE id = ? AND kind = ?
         AND EXISTS (SELECT 1 FROM json_each(event.tags) AS tag
                     WHERE json_extract(tag.value, '$[0]') = ?
                       AND json_extract(tag.value, '$[1]') = ?))";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(conn, sql, -1, &stmt, nullptr) != SQLITE_OK) {
    console->error("{}", sqlite3_errmsg(conn));
    return -1;
  }
  sqlite3_bind_text(stmt, 1, id.data(), (int)id.size(), SQLITE_TRANSIENT);
  sqlite3_bind_int(stmt, 2, kind);
  sqlite3_bind_text(stmt, 3, tag[0].data(), (int)tag[0].size(), SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 4, tag[1].data(), (int)tag[1].size(), SQLITE_TRANSIENT);
  auto ret = sqlite3_step(stmt);
  if (ret != SQLITE_DONE) {
    console->error("{}", sqlite3_errmsg(conn));
    sqlite3_finalize(stmt);
    return -1;
  }
  sqlite3_finalize(stmt);
  return sqlite3_changes(conn);
}

static int delete_all_events_by_pubkey(const std::string &pubkey,
                                       std::time_t created_at) {
  const auto sql =
      R"(DELETE FROM event WHERE pubkey = ? AND created_at <= ? AND kind != 62)";
  sqlite3_stmt *stmt = nullptr;
  auto ret = sqlite3_prepare_v2(conn, sql, (int)strlen(sql), &stmt, nullptr);
  if (ret != SQLITE_OK) {
    console->error("{}", sqlite3_errmsg(conn));
    return -1;
  }
  sqlite3_bind_text(stmt, 1, pubkey.data(), (int)pubkey.size(),
                    SQLITE_TRANSIENT);
  sqlite3_bind_int64(stmt, 2, created_at);

  ret = sqlite3_step(stmt);
  if (ret != SQLITE_DONE) {
    console->error("{}", sqlite3_errmsg(conn));
    sqlite3_finalize(stmt);
    return -1;
  }
  sqlite3_finalize(stmt);

  return sqlite3_changes(conn);
}

static void sqlite3_trace_callback(void * /*user_data*/,
                                   const char *statement) {
  assert(statement);
  console->debug("{}", statement);
}

static void storage_init(const std::string &dsn) {
  console->debug("initialize storage");

  auto ret = sqlite3_open_v2(dsn.c_str(), &conn,
                             SQLITE_OPEN_URI | SQLITE_OPEN_READWRITE |
                                 SQLITE_OPEN_CREATE | SQLITE_OPEN_NOMUTEX,
                             nullptr);
  if (ret != SQLITE_OK) {
    console->error("{}", sqlite3_errmsg(conn));
    throw std::runtime_error("unable to connect to database");
  }
  sqlite3_trace(conn, sqlite3_trace_callback, nullptr);

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
    PRAGMA journal_mode = WAL;
    PRAGMA busy_timeout = 5000;
    PRAGMA synchronous = NORMAL;
    PRAGMA cache_size = -262144;
    PRAGMA foreign_keys = true;
    PRAGMA temp_store = memory;
  )";
  ret = sqlite3_exec(conn, sql, nullptr, nullptr, nullptr);
  if (ret != SQLITE_OK) {
    console->error("{}", sqlite3_errmsg(conn));
    throw std::runtime_error("unable to connect to database");
  }
}

static void storage_deinit() { sqlite3_close_v2(conn); }

void storage_context_init_sqlite3(storage_context_t &ctx) {
  ctx.init = storage_init;
  ctx.deinit = storage_deinit;
  ctx.get_event_by_id = get_event_by_id;
  ctx.insert_record = insert_record;
  ctx.delete_record_by_id_and_pubkey = delete_record_by_id_and_pubkey;
  ctx.delete_record_by_kind_and_pubkey = delete_record_by_kind_and_pubkey;
  ctx.delete_record_by_kind_and_pubkey_and_dtag =
      delete_record_by_kind_and_pubkey_and_dtag;
  ctx.delete_record_by_id_and_kind_and_ptag =
      delete_record_by_id_and_kind_and_ptag;
  ctx.delete_all_events_by_pubkey = delete_all_events_by_pubkey;
  ctx.send_records = send_records;
}
