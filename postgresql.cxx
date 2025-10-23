#include "cagliostr.hxx"
#include <iostream>
#include <string>
#include <vector>
#include <pqxx/pqxx>
#include <nlohmann/json.hpp>

static pqxx::connection *conn;

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

static bool insert_record(const event_t& ev) {
  try {
    nlohmann::json jtags = nlohmann::json::array();
    for (const auto& tag : ev.tags) {
      jtags.push_back(nlohmann::json(tag));
    }
    std::string tags_str = jtags.dump();

    pqxx::work txn(*conn);
    pqxx::result r = txn.exec(R"(
      INSERT INTO event (
        id, pubkey, created_at, kind, tags, content, sig)
	    VALUES ($1, $2, $3, $4, $5, $6, $7)
	    ON CONFLICT (id) DO NOTHING)",
      {ev.id, ev.pubkey, ev.created_at, ev.kind, tags_str, ev.content, ev.sig}
    );
    txn.commit();
    return r.affected_rows() > 0;
  } catch (const std::exception& e) {
    console->error("{}", e.what());
    exit(-1);
  }
}

static std::string escape(const std::string &data) {
  std::string result;
  for (const auto c : data) {
    if (c == '%') {
      result.push_back('%');
    }
    result.push_back(c);
  }
  return result;
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

static std::string pno(size_t n) {
  return "$" + std::to_string(n + 1);
}

static std::string make_placeholders(size_t n, int& pno) {
    std::string placeholders;
    for (size_t i = 0; i < n; ++i) {
        placeholders += "$" + std::to_string(pno + i + 1);
        if (i < n - 1) {
            placeholders += ",";
        }
    }
    pno += n;
    return placeholders;
}


static bool send_records(std::function<void(const nlohmann::json &)> sender,
                  const std::string &sub, const std::vector<filter_t> &filters,
                  bool do_count) {
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
    pqxx::params params;
    std::vector<std::string> conditions;
    int pno = 0;
    if (!filter.ids.empty()) {
      if (filter.ids.size() == 1) {
        conditions.push_back("id = $" + std::to_string(++pno));
        params.append(filter.ids.front());
      } else {
        std::string condition;
        for (const auto &id : filter.ids) {
          condition += std::to_string(++pno) + ",";
          params.append(id);
        }
        condition.pop_back();
        conditions.push_back("id in (" + condition + ")");
      }
    }
    if (!filter.authors.empty()) {
      if (filter.authors.size() == 1) {
        conditions.push_back("pubkey = $" + std::to_string(++pno));
        params.append(filter.authors.front());
      } else {
        std::string condition;
        for (const auto &author : filter.authors) {
          condition += "$" + std::to_string(++pno) + ",";
          params.append(author);
        }
        condition.pop_back();
        conditions.push_back("pubkey in (" + condition + ")");
      }
    }
    if (!filter.kinds.empty()) {
      if (filter.kinds.size() == 1) {
        conditions.push_back("kind = $" + std::to_string(++pno));
        params.append(filter.kinds.front());
      } else {
        std::string condition;
        for (const auto &kind : filter.kinds) {
          condition += "$" + std::to_string(++pno) + ",";
          params.append(kind);
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
        for (decltype(tag.size()) i = 0; i < tag.size(); i++) {
          params.append(tag[i]);
        }
        match.push_back(R"(tagvalues && ARRAY[)" + make_placeholders(tag.size(), pno)+"]");
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
      params.append("%" + escape(filter.search) + "%");
      conditions.push_back(R"(content LIKE $)" + std::to_string(++pno) + R"( ESCAPE '\')");
    }
    if (!conditions.empty()) {
      sql += " WHERE " + join(conditions, " AND ");
    }
    if (!do_count) {
      sql += " ORDER BY created_at DESC LIMIT " + std::to_string(limit);
    }

    std::cout << "Final SQL: " << sql << std::endl;
    pqxx::work txn(*conn);
    pqxx::result r = txn.exec(sql, params);
    txn.commit();

    if (do_count) {
      count += r.one_field().as<int>();
    } else {
      for (const auto& row : r) {
        nlohmann::json ej;
        ej["id"] = row["id"].c_str();
        ej["pubkey"] = row["pubkey"].c_str();
        ej["created_at"] = row["created_at"].as<int>();
        ej["kind"] = row["kind"].as<int>();
        const char* j = row["tags"].c_str();
        ej["tags"] = nlohmann::json::parse(j);
        ej["content"] = row["content"].c_str();
        ej["sig"] = row["sig"].c_str();

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
  const auto sql = R"(DELETE FROM event WHERE id = $1)";
  pqxx::work txn(*conn);
  try {
    pqxx::result r = txn.exec(sql, pqxx::params{id});
    txn.commit();
    return r.affected_rows();
  } catch (const std::exception& e) {
    console->error("{}", e.what());
    return -1;
  }
}

static int delete_record_by_kind_and_pubkey(int kind, const std::string &pubkey, std::time_t created_at) {
  const auto sql = R"(DELETE FROM event WHERE kind = $1 AND pubkey = $2 AND created_at < $3)";
  pqxx::work txn(*conn);
  try {
    pqxx::result r = txn.exec(sql, pqxx::params{kind, pubkey, created_at});
    return r.affected_rows();
  } catch (const std::exception& e) {
    console->error("{}", e.what());
    return -1;
  }
}

static int delete_record_by_kind_and_pubkey_and_dtag(
    int kind, const std::string &pubkey, const std::vector<std::string> &tag, std::time_t created_at) {
  std::string sql =
      R"(SELECT id FROM event WHERE kind = ? AND pubkey = ? AND tags LIKE ? AND created_at < ?)";

  nlohmann::json data = tag;

  pqxx::work txn(*conn);
  pqxx::result r = txn.exec(
    "SELECT id FROM event WHERE kind = $1 AND pubkey = $2 AND tags::text LIKE $3 AND created_at < $4",
    {kind, pubkey, "%" + escape(data.dump()) + "%", created_at}
  );
  data.clear();

  std::vector<std::string> ids;
  for (const auto& row : r) {
    ids.push_back(row["id"].c_str());
  }

  if (ids.empty()) {
    return 0;
  }

  std::ostringstream os;
  std::string condition;
  for (decltype(ids.size()) i = 0; i < ids.size(); i++) {
    condition += "?,";
  }
  condition.pop_back();

  pqxx::work txn2(*conn);
  pqxx::params params;
  for (decltype(ids.size()) i = 0; i < ids.size(); i++) {
    params.append(ids[i]);
  }
  r = txn.exec(
    pqxx::prepped{ "DELETE FROM event WHERE id in (" + condition + ")"},
    params
  );

  return r.affected_rows();
}

static void storage_init(const std::string& dsn) {
  console->debug("initialize storage");

  try {
    conn = new pqxx::connection(dsn);
    if (!conn->is_open()) {
      console->debug("unable to connect to database");
      exit(-1);
    }

    pqxx::work txn(*conn);
    txn.exec(R"(
      CREATE OR REPLACE FUNCTION tags_to_tagvalues(jsonb) RETURNS text[]
          AS 'SELECT array_agg(t->>1) FROM (SELECT jsonb_array_elements($1) AS t)s WHERE length(t->>0) = 1;'
          LANGUAGE SQL
          IMMUTABLE
          RETURNS NULL ON NULL INPUT;
      
      CREATE TABLE IF NOT EXISTS event (
        id text NOT NULL,
        pubkey text NOT NULL,
        created_at integer NOT NULL,
        kind integer NOT NULL,
        tags jsonb NOT NULL,
        content text NOT NULL,
        sig text NOT NULL,
      
        tagvalues text[] GENERATED ALWAYS AS (tags_to_tagvalues(tags)) STORED
      );
      
      CREATE UNIQUE INDEX IF NOT EXISTS ididx ON event USING btree (id text_pattern_ops);
      CREATE INDEX IF NOT EXISTS pubkeyprefix ON event USING btree (pubkey text_pattern_ops);
      CREATE INDEX IF NOT EXISTS timeidx ON event (created_at DESC);
      CREATE INDEX IF NOT EXISTS kindidx ON event (kind);
      CREATE INDEX IF NOT EXISTS kindtimeidx ON event(kind,created_at DESC);
      CREATE INDEX IF NOT EXISTS arbitrarytagvalues ON event USING gin (tagvalues);
    )");
    txn.commit();
  } catch (const std::exception& e) {
    console->error("{}",  e.what());
    exit(-1);
  }
}

static void storage_deinit() {
  conn->close();
}

void storage_context_init_postgresql(storage_context& ctx) {
  ctx.init = storage_init;
  ctx.deinit = storage_deinit;
  ctx.insert_record = insert_record;
  ctx.delete_record_by_id = delete_record_by_id;
  ctx.delete_record_by_kind_and_pubkey = delete_record_by_kind_and_pubkey;
  ctx.delete_record_by_kind_and_pubkey_and_dtag = delete_record_by_kind_and_pubkey_and_dtag;
  ctx.send_records = send_records;
}

