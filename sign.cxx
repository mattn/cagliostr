#include "cagliostr.hxx"
#include <ctime>
#include <iomanip>
#include <iostream>
#include <sstream>

#include <openssl/evp.h>

#include <secp256k1.h>
#include <secp256k1_schnorrsig.h>

static inline std::vector<uint8_t> hex2bytes(const std::string &hex) {
  std::vector<uint8_t> bytes;
  for (decltype(hex.length()) i = 0; i < hex.length(); i += 2) {
    std::string s = hex.substr(i, 2);
    auto byte = static_cast<uint8_t>(strtol(s.c_str(), nullptr, 16));
    bytes.push_back(byte);
  }
  return bytes;
}

static inline std::string digest2hex(const uint8_t data[32]) {
  std::stringstream ss;
  ss << std::hex;
  for (size_t i = 0; i < 32; ++i) {
    ss << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
  }
  return ss.str();
}

static bool signature_verify(const std::vector<uint8_t> &bytes_sig,
                             const std::vector<uint8_t> &bytes_pub,
                             const uint8_t digest[32]) {
#define secp256k1_context_flags                                                \
  (SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY)
  secp256k1_context *ctx = secp256k1_context_create(secp256k1_context_flags);
  secp256k1_xonly_pubkey pub;
  if (!secp256k1_xonly_pubkey_parse(ctx, &pub, bytes_pub.data())) {
    secp256k1_context_destroy(ctx);
    return false;
  }

  auto result = secp256k1_schnorrsig_verify(ctx, bytes_sig.data(), digest,
#ifdef SECP256K1_SCHNORRSIG_EXTRAPARAMS_INIT
                                            32,
#endif
                                            &pub);
  secp256k1_context_destroy(ctx);
  return result;
}

static bool check_delegation(const event_t &ev,
                             const std::string &delegator_pubkey,
                             const std::string &conditions,
                             const std::string &delegation_sig) {
  if (!conditions.empty()) {
    std::istringstream iss(conditions);
    std::string condition;
    while (std::getline(iss, condition, '&')) {
      auto eq_pos = condition.find('=');
      if (eq_pos == std::string::npos)
        continue;

      auto key = condition.substr(0, eq_pos);
      auto value = condition.substr(eq_pos + 1);

      if (key == "kind") {
        if (std::to_string(ev.kind) != value) {
          return false;
        }
      } else if (key == "created_at") {
        auto op_pos = value.find_first_of("<>");
        if (op_pos != std::string::npos) {
          char op = value[op_pos];
          auto timestamp = std::stoll(value.substr(op_pos + 1));
          if (op == '<' && ev.created_at >= timestamp) {
            return false;
          } else if (op == '>' && ev.created_at <= timestamp) {
            return false;
          }
        }
      }
    }
  }

  std::stringstream delegation_data;
  delegation_data << "nostr:delegation:" << ev.pubkey << ":" << conditions;
  auto delegation_str = delegation_data.str();

  uint8_t delegation_digest[32] = {0};
  EVP_Digest(delegation_str.data(), delegation_str.size(), delegation_digest,
             nullptr, EVP_sha256(), nullptr);

  auto bytes_delegation_sig = hex2bytes(delegation_sig);
  auto bytes_delegator_pub = hex2bytes(delegator_pubkey);

  return signature_verify(bytes_delegation_sig, bytes_delegator_pub,
                          delegation_digest);
}

bool check_event(const event_t &ev) {
  nlohmann::json check = nlohmann::json::array({
      0,
      ev.pubkey,
      ev.created_at,
      ev.kind,
      ev.tags,
      ev.content,
  });
  auto dump = check.dump();
  check.clear();

  uint8_t digest[32] = {0};
  EVP_Digest(dump.data(), dump.size(), digest, nullptr, EVP_sha256(), nullptr);

  auto id = digest2hex(digest);
  if (id != ev.id) {
    return false;
  }

  auto bytes_sig = hex2bytes(ev.sig);
  auto bytes_pub = hex2bytes(ev.pubkey);
  if (!signature_verify(bytes_sig, bytes_pub, digest)) {
    return false;
  }

  for (const auto &tag : ev.tags) {
    if (tag.size() >= 4 && tag[0] == "delegation") {
      const auto &delegator_pubkey = tag[1];
      const auto &conditions = tag[2];
      const auto &delegation_sig = tag[3];

      if (!check_delegation(ev, delegator_pubkey, conditions, delegation_sig)) {
        return false;
      }
    }
  }

  return true;
}
