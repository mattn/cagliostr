#include "cagliostr.hxx"
#include <sstream>

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
      if (delim)
        s += delim;
      s += v[i];
    }
  }
  return s;
}

bool insert_record(event_t &ev) {
  const auto sql =
      R"(INSERT INTO event (id, pubkey, created_at, kind, tags, content, sig) VALUES ($1, $2, $3, $4, $5, $6, $7))";
  sqlite3_stmt *stmt = nullptr;
  auto ret = sqlite3_prepare(conn, sql, (int)strlen(sql), &stmt, nullptr);
  if (ret != SQLITE_OK) {
    spdlog::error("{}", sqlite3_errmsg(conn));
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
    spdlog::error("{}", sqlite3_errmsg(conn));
    sqlite3_free(stmt);
    return false;
  }
  sqlite3_finalize(stmt);

  return true;
}

bool send_records(ws28::Client *client, std::string &sub,
                  std::vector<filter_t> &filters, bool do_count) {
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
      std::vector<std::string> match;
      for (const auto &id : filter.ids) {
        params.push_back({.t = 1, .s = id + "%"});
        match.push_back("id LIKE ?");
      }
      conditions.push_back("(" + join(match, " OR ") + ")");
    }
    if (!filter.authors.empty()) {
      std::vector<std::string> match;
      for (const auto &author : filter.authors) {
        params.push_back({.t = 1, .s = author + "%"});
        match.push_back("pubkey LIKE ?");
      }
      conditions.push_back("(" + join(match, " OR ") + ")");
    }
    if (!filter.kinds.empty()) {
      std::string condition;
      for (const auto &kind : filter.kinds) {
        condition += "?,";
        params.push_back({.t = 0, .n = kind});
      }
      condition.pop_back();
      conditions.push_back("kind in (" + condition + ")");
    }
    if (!filter.tags.empty()) {
      std::vector<std::string> match;
      for (const auto &tag : filter.tags) {
        nlohmann::json data = tag;
        params.push_back({.t = 1, .s = data.dump()});
        match.push_back("tags LIKE ?");
      }
      conditions.push_back("(" + join(match, " OR ") + ")");
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
      params.push_back({.t = 1, .s = "%" + filter.search + "%"});
      conditions.push_back("content LIKE ?");
    }
    if (!conditions.empty()) {
      sql += " WHERE " + join(conditions, " AND ");
    }
    sql += " ORDER BY created_at DESC LIMIT ?";

    sqlite3_stmt *stmt = nullptr;
    auto ret =
        sqlite3_prepare(conn, sql.data(), (int)sql.size(), &stmt, nullptr);
    if (ret != SQLITE_OK) {
      spdlog::error("{}", sqlite3_errmsg(conn));
      return false;
    }

    for (size_t i = 0; i < params.size(); i++) {
      switch (params.at(i).t) {
      case 0:
        sqlite3_bind_int(stmt, i + 1, params.at(i).n);
        break;
      case 1:
        sqlite3_bind_text(stmt, i + 1, params.at(i).s.data(),
                          (int)params.at(i).s.size(), nullptr);
        break;
      }
    }

    sqlite3_bind_int(stmt, params.size() + 1, limit);
    if (do_count) {
      ret = sqlite3_step(stmt);
      if (ret == SQLITE_DONE) {
        spdlog::error("{}", sqlite3_errmsg(conn));
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

        nlohmann::json reply = {"EVENT", sub, ej};
        relay_send(client, reply);
      }
      sqlite3_finalize(stmt);
    }
  }

  if (do_count) {
    nlohmann::json cc;
    cc["count"] = count;
    nlohmann::json reply = {"COUNT", sub, cc};
    relay_send(client, reply);
  }
  return true;
}

bool delete_record_by_id(const std::string &id) {
  const auto sql = R"(DELETE FROM event WHERE id = ?)";
  sqlite3_stmt *stmt = nullptr;
  auto ret = sqlite3_prepare(conn, sql, (int)strlen(sql), &stmt, nullptr);
  if (ret != SQLITE_OK) {
    spdlog::error("{}", sqlite3_errmsg(conn));
    return false;
  }
  sqlite3_bind_text(stmt, 1, id.data(), (int)id.size(), nullptr);

  ret = sqlite3_step(stmt);
  if (ret != SQLITE_DONE) {
    spdlog::error("{}", sqlite3_errmsg(conn));
    sqlite3_free(stmt);
    return false;
  }
  sqlite3_finalize(stmt);

  return true;
}

bool delete_record_by_kind_and_pubkey(int kind, const std::string &pubkey) {
  const auto sql = R"(DELETE FROM event WHERE kind = ? AND pubkey = ?)";
  sqlite3_stmt *stmt = nullptr;
  auto ret = sqlite3_prepare(conn, sql, (int)strlen(sql), &stmt, nullptr);
  if (ret != SQLITE_OK) {
    spdlog::error("{}", sqlite3_errmsg(conn));
    return false;
  }
  sqlite3_bind_int(stmt, 1, kind);
  sqlite3_bind_text(stmt, 2, pubkey.data(), (int)pubkey.size(), nullptr);

  ret = sqlite3_step(stmt);
  if (ret != SQLITE_DONE) {
    spdlog::error("{}", sqlite3_errmsg(conn));
    sqlite3_free(stmt);
    return false;
  }
  sqlite3_finalize(stmt);

  return true;
}

bool delete_record_by_kind_and_pubkey_and_dtag(
    int kind, const std::string &pubkey, const std::vector<std::string> &tag) {
  std::string sql =
      R"(SELECT id FROM event WHERE kind = ? AND pubkey = ? AND tags LIKE ?)";

  sqlite3_stmt *stmt = nullptr;
  auto ret = sqlite3_prepare(conn, sql.data(), (int)sql.size(), &stmt, nullptr);
  if (ret != SQLITE_OK) {
    spdlog::error("{}", sqlite3_errmsg(conn));
    sqlite3_free(stmt);
    return false;
  }

  nlohmann::json data = tag;
  sqlite3_bind_int(stmt, 1, kind);
  sqlite3_bind_text(stmt, 2, pubkey.data(), (int)pubkey.size(), nullptr);
  sqlite3_bind_text(stmt, 3, data.dump().data(), (int)data.dump().size(),
                    nullptr);

  std::vector<std::string> ids;
  while (true) {
    ret = sqlite3_step(stmt);
    if (ret == SQLITE_DONE) {
      break;
    }
    ids.push_back((char *)sqlite3_column_text(stmt, 0));
  }
  sqlite3_finalize(stmt);

  std::ostringstream os;
  std::string condition;
  for (size_t i = 0; i < ids.size(); i++) {
    condition += "?,";
  }
  condition.pop_back();
  sql = "DELETE FROM event WHERE id in (" + condition + ")";

  stmt = nullptr;
  ret = sqlite3_prepare(conn, sql.data(), (int)sql.size(), &stmt, nullptr);
  if (ret != SQLITE_OK) {
    spdlog::error("{}", sqlite3_errmsg(conn));
    return false;
  }
  for (size_t i = 0; i < ids.size(); i++) {
    sqlite3_bind_text(stmt, i + 1, ids[i].data(), (int)ids[i].size(), nullptr);
  }

  ret = sqlite3_step(stmt);
  if (ret != SQLITE_DONE) {
    spdlog::error("{}", sqlite3_errmsg(conn));
    sqlite3_free(stmt);
    return false;
  }
  sqlite3_finalize(stmt);
  return true;
}
