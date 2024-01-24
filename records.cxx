#include "cagliostr.hxx"

static std::string make_in_query(const std::string &name,
                                 const nlohmann::json &data) {
  auto s = data.dump();
  s = s.substr(1, s.size() - 2);
  return " " + name + " in (" + s + ")";
}

bool insert_record(event_t &ev) {
  const auto sql = R"(
    INSERT INTO event (id, pubkey, created_at, kind, tags, content, sig)
    VALUES ($1, $2, $3, $4, $5, $6, $7)
  )";
  sqlite3_stmt *stmt = nullptr;
  spdlog::debug("{}", sql);
  auto ret = sqlite3_prepare(conn, sql, (int)strlen(sql), &stmt, nullptr);
  if (ret != SQLITE_OK) {
    fprintf(stderr, "%s\n", sqlite3_errmsg(conn));
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
    fprintf(stderr, "%s\n", sqlite3_errmsg(conn));
    sqlite3_free(stmt);
    return false;
  }
  sqlite3_finalize(stmt);

  return true;
}

bool send_records(ws28::Client *client, std::string &sub,
                  std::vector<filter_t> &filters, bool do_count) {
  std::string sql;
  if (do_count) {
    sql = R"(
    SELECT
      COUNT(id)
    FROM event WHERE 1 = 1
    )";
  } else {
    sql = R"(
    SELECT
      id, pubkey, created_at, kind, tags, content, sig
    FROM event WHERE 1 = 1
    )";
  }

  typedef struct {
    int t{};
    int n{};
    std::string s{};
  } param_t;
  std::vector<param_t> params;
  auto limit = 500;
  for (const auto &filter : filters) {
    if (!filter.ids.empty()) {
      std::string condition;
      for (const auto &id : filter.ids) {
        condition += "?,";
        params.push_back({.t = 1, .s = id});
      }
      condition.pop_back();
      sql += " AND id in (" + condition + ")";
    }
    if (!filter.authors.empty()) {
      std::string condition;
      for (const auto &author : filter.authors) {
        condition += "?,";
        params.push_back({.t = 1, .s = author});
      }
      condition.pop_back();
      sql += " AND pubkey in (" + condition + ")";
    }
    if (!filter.kinds.empty()) {
      sql += " AND " + make_in_query("kind", filter.kinds);
      std::string condition;
      for (const auto &kind : filter.kinds) {
        condition += "?,";
        params.push_back({.t = 0, .n = kind});
      }
      condition.pop_back();
      sql += " AND kind in (" + condition + ")";
    }
    if (!filter.tags.empty()) {
      std::string condition;
      for (const auto &tag : filter.tags) {
        if (!condition.empty()) {
          condition += " OR ";
        }
        condition += "tags LIKE ?";
        nlohmann::json data = tag;
        params.push_back({.t = 1, .s = data.dump()});
      }
      sql += " AND (" + condition + ")";
    }
    if (filter.since != 0) {
      std::ostringstream os;
      os << filter.since;
      sql += " AND created_at >= " + os.str();
    }
    if (filter.until != 0) {
      std::ostringstream os;
      os << filter.until;
      sql += " AND created_at <= " + os.str();
    }
    if (filter.limit > 0 && filter.limit < limit) {
      limit = filter.limit;
    }
    if (!filter.search.empty()) {
      sql += " AND content LIKE ?";
      params.push_back({.t = 1, .s = "%" + filter.search + "%"});
    }
  }
  sql += " ORDER BY created_at DESC LIMIT ?";
  spdlog::debug("{}", sql);

  sqlite3_stmt *stmt = nullptr;
  auto ret = sqlite3_prepare(conn, sql.data(), (int)sql.size(), &stmt, nullptr);
  if (ret != SQLITE_OK) {
    fprintf(stderr, "%s\n", sqlite3_errmsg(conn));
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
      fprintf(stderr, "%s\n", sqlite3_errmsg(conn));
      return false;
    }
    nlohmann::json cc;
    cc["count"] = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    nlohmann::json reply = {"COUNT", sub, cc};
    relay_send(client, reply);
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

  return true;
}
