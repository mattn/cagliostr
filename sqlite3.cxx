#include "cagliostr.hxx"
#include <ctime>
#include <sstream>
#include <iostream>
#include <sstream>

#include <sqlite3.h>

// global variables
static sqlite3 *conn = nullptr;

#define PARAM_TYPE_NUMBER (0)
#define PARAM_TYPE_STRING (1)

typedef struct param_t {
  int t{};
  int n{};
  std::string s{};
} param_t;

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

static bool insert_record(const event_t &ev) {
  const auto sql =
      R"(INSERT INTO event (id, pubkey, created_at, kind, tags, content, sig) VALUES ($1, $2, $3, $4, $5, $6, $7))";
  sqlite3_stmt *stmt = nullptr;
  auto ret = sqlite3_prepare_v2(conn, sql, -1, &stmt, nullptr);
  if (ret != SQLITE_OK) {
    console->error("{}", sqlite3_errmsg(conn));
    return false;
  }
  nlohmann::json tags = ev.tags;
  auto s = tags.dump();
  sqlite3_bind_text(stmt, 1, ev.id.data(), (int)ev.id.size(), nullptr);
  sqlite3_bind_text(stmt, 2, ev.pubkey.data(), (int)ev.pubkey.size(), nullptr);
  sqlite3_bind_int(stmt, 3, (int)ev.created_at);
  sqlite3_bind_int(stmt, 4, ev.kind);
  sqlite3_bind_text(stmt, 5, s.data(), (int)s.size(), nullptr);
  sqlite3_bind_text(stmt, 6, ev.content.data(), (int)ev.content.size(),
                    nullptr);
  sqlite3_bind_text(stmt, 7, ev.sig.data(), (int)ev.sig.size(), nullptr);

  ret = sqlite3_step(stmt);
  if (ret != SQLITE_DONE) {
    console->error("{}", sqlite3_errmsg(conn));
    sqlite3_finalize(stmt);
    return false;
  }
  sqlite3_finalize(stmt);

  return true;
}

static bool is_expired(std::vector<std::vector<std::string>> &tags) {
  time_t now = time(nullptr), expiration;
  for (const auto &tag : tags) {
    if (tag.size() == 2 && tag[0] == "expiration") {
      std::stringstream ss;
      ss << tag[1];
      ss >> expiration;
      if (expiration <= now) {
        return true;
      }
    }
  }
  return false;
}

static bool send_records(std::function<void(const nlohmann::json &)> sender,
                         const std::string &sub,
                         const std::vector<filter_t> &filters, bool do_count) {
  auto count = 0;
  for (const auto &filter : filters) {
    std::string sql;
    if (do_count) {
      sql = R"(SELECT COUNT(id) FROM event)";
    } else {
      sql =
          R"(SELECT id, pubkey, created_at, kind, tags, content, sig FROM event)";
    }

    auto limit = 500;
    std::vector<param_t> params;
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
    if (!filter.tags.empty()) {
      std::vector<std::string> match;
      for (const auto &tag : filter.tags) {
        if (tag.size() < 2) {
          continue;
        }
        auto first = tag[0];
        for (decltype(tag.size()) i = 1; i < tag.size(); i++) {
          nlohmann::json data = {first, tag[i]};
          params.push_back(
              {.t = PARAM_TYPE_STRING, .s = "%" + escape(data.dump()) + "%"});
          match.push_back(R"(tags LIKE ? ESCAPE '\')");
        }
      }
      if (match.size() == 1) {
        conditions.push_back(match.front());
      } else {
        conditions.push_back("(" + join(match, " OR ") + ")");
      }
    }
    if (filter.since != 0) {
      std::ostringstream os;
      os << filter.since;
      conditions.push_back("created_at >= " + os.str());
    }
    if (filter.until != 0) {
      std::ostringstream os;
      os << filter.until;
      conditions.push_back("created_at <= " + os.str());
    }
    if (filter.limit > 0 && filter.limit < limit) {
      limit = filter.limit;
    }
    if (!filter.search.empty()) {
      params.push_back(
          {.t = PARAM_TYPE_STRING, .s = "%" + escape(filter.search) + "%"});
      conditions.push_back(R"(content LIKE ? ESCAPE '\')");
    }
    if (!conditions.empty()) {
      sql += " WHERE " + join(conditions, " AND ");
    }
    if (!do_count) {
      sql += " ORDER BY created_at DESC LIMIT ?";
    }
    if (!do_count) {
      sqlite3_bind_int(stmt, params.size() + 1, limit);
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
                          (int)params.at(i).s.size(), nullptr);
        break;
      }
    }

    sqlite3_bind_int(stmt, params.size() + 1, limit);
    if (do_count) {
      ret = sqlite3_step(stmt);
      if (ret == SQLITE_DONE) {
        console->error("{}", sqlite3_errmsg(conn));
        sqlite3_finalize(stmt);
        return false;
      }
      count += sqlite3_column_int(stmt, 0);
      sqlite3_finalize(stmt);
    } else {
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

        if (ej["tags"].is_array() && ej["tags"].size() > 0) {
          std::vector<std::vector<std::string>> tags;
          ej["tags"].get_to(tags);
          if (is_expired(tags)) {
            continue;
          }
        }

        nlohmann::json reply = {"EVENT", sub, ej};
        sender(reply);
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

static int delete_record_by_id(const std::string &id) {
  const auto sql = R"(DELETE FROM event WHERE id = ?)";
  sqlite3_stmt *stmt = nullptr;
  auto ret = sqlite3_prepare_v2(conn, sql, (int)strlen(sql), &stmt, nullptr);
  if (ret != SQLITE_OK) {
    console->error("{}", sqlite3_errmsg(conn));
    return -1;
  }
  sqlite3_bind_text(stmt, 1, id.data(), (int)id.size(), nullptr);

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
  sqlite3_bind_text(stmt, 2, pubkey.data(), (int)pubkey.size(), nullptr);
  sqlite3_bind_int(stmt, 3, created_at);

  ret = sqlite3_step(stmt);
  if (ret != SQLITE_DONE) {
    console->error("{}", sqlite3_errmsg(conn));
    sqlite3_finalize(stmt);
    return -1;
  }
  sqlite3_finalize(stmt);

  return sqlite3_changes(conn);
}

static int
delete_record_by_kind_and_pubkey_and_dtag(int kind, const std::string &pubkey,
                                          const std::vector<std::string> &tag,
                                          std::time_t created_at) {
  std::string sql =
      R"(SELECT id FROM event WHERE kind = ? AND pubkey = ? AND tags LIKE ? AND created_at < ?)";

  sqlite3_stmt *stmt = nullptr;
  auto ret =
      sqlite3_prepare_v2(conn, sql.data(), (int)sql.size(), &stmt, nullptr);
  if (ret != SQLITE_OK) {
    console->error("{}", sqlite3_errmsg(conn));
    return -1;
  }

  nlohmann::json data = tag;
  auto s = "%" + escape(data.dump()) + "%";
  data.clear();
  sqlite3_bind_int(stmt, 1, kind);
  sqlite3_bind_text(stmt, 2, pubkey.data(), (int)pubkey.size(), nullptr);
  sqlite3_bind_text(stmt, 3, s.data(), (int)s.size(), nullptr);
  sqlite3_bind_int(stmt, 4, created_at);

  std::vector<std::string> ids;
  while (true) {
    ret = sqlite3_step(stmt);
    if (ret == SQLITE_DONE) {
      break;
    }
    ids.push_back((char *)sqlite3_column_text(stmt, 0));
  }
  sqlite3_finalize(stmt);

  if (ids.empty()) {
    return 0;
  }

  std::ostringstream os;
  std::string condition;
  for (decltype(ids.size()) i = 0; i < ids.size(); i++) {
    condition += "?,";
  }
  condition.pop_back();
  sql = "DELETE FROM event WHERE id in (" + condition + ")";

  stmt = nullptr;
  ret = sqlite3_prepare_v2(conn, sql.data(), (int)sql.size(), &stmt, nullptr);
  if (ret != SQLITE_OK) {
    console->error("{}", sqlite3_errmsg(conn));
    return -1;
  }
  for (decltype(ids.size()) i = 0; i < ids.size(); i++) {
    sqlite3_bind_text(stmt, i + 1, ids[i].data(), (int)ids[i].size(), nullptr);
  }

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
    exit(-1);
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
    PRAGMA cache_size = 1000000000;
    PRAGMA foreign_keys = true;
    PRAGMA temp_store = memory;
  )";
  ret = sqlite3_exec(conn, sql, nullptr, nullptr, nullptr);
  if (ret != SQLITE_OK) {
    console->error("{}", sqlite3_errmsg(conn));
    exit(-1);
  }
}

static void storage_deinit() { sqlite3_close_v2(conn); }

void storage_context_init_sqlite3(storage_context &ctx) {
  ctx.init = storage_init;
  ctx.deinit = storage_deinit;
  ctx.insert_record = insert_record;
  ctx.delete_record_by_id = delete_record_by_id;
  ctx.delete_record_by_kind_and_pubkey = delete_record_by_kind_and_pubkey;
  ctx.delete_record_by_kind_and_pubkey_and_dtag =
      delete_record_by_kind_and_pubkey_and_dtag;
  ctx.send_records = send_records;
}
