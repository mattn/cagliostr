#ifndef _CAGLIOSTR_H_
#define _CAGLIOSTR_H_

#include <algorithm>
#include <exception>
#include <iostream>
#include <sstream>
#include <string>

#include <sqlite3.h>

#include <libbech32/bech32.h>
#include <nlohmann/json.hpp>
#include <openssl/evp.h>

#include <secp256k1.h>
#include <secp256k1_schnorrsig.h>

#include <spdlog/cfg/env.h>
#include <spdlog/spdlog.h>

#include <Server.h>

#include "version.h"

typedef struct event_t {
  std::string id;
  std::string pubkey;
  std::time_t created_at;
  int kind;
  std::vector<std::vector<std::string>> tags;
  std::string content;
  std::string sig;
} event_t;

typedef struct filter_t {
  std::vector<std::string> ids{};
  std::vector<std::string> authors{};
  std::vector<int> kinds{};
  std::vector<std::vector<std::string>> tags{};
  std::time_t since{};
  std::time_t until{};
  int limit{500};
  std::string search;
} filter_t;

typedef struct subscriber_t {
  std::string sub;
  ws28::Client *client{};
  std::vector<filter_t> filters;
} subscriber_t;

extern sqlite3 *conn;

bool insert_record(event_t &);
bool send_records(ws28::Client *, std::string &, std::vector<filter_t> &, bool);
void relay_send(ws28::Client *, nlohmann::json &);

#endif
