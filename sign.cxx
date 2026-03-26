#include "cagliostr.hxx"
#include <ctime>
#include <iomanip>
#include <iostream>
#include <sstream>

#include <openssl/evp.h>

#include <secp256k1.h>
#include <secp256k1_schnorrsig.h>

static inline int hex_value(char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  }
  if (c >= 'A' && c <= 'F') {
    return c - 'A' + 10;
  }
  return -1;
}

static inline std::vector<uint8_t> hex2bytes(const std::string &hex) {
  std::vector<uint8_t> bytes;
  bytes.reserve(hex.size() / 2);
  for (size_t i = 0; i + 1 < hex.size(); i += 2) {
    auto hi = hex_value(hex[i]);
    auto lo = hex_value(hex[i + 1]);
    if (hi < 0 || lo < 0) {
      return {};
    }
    bytes.push_back(static_cast<uint8_t>((hi << 4) | lo));
  }
  return bytes;
}

static inline std::string digest2hex(const uint8_t data[32]) {
  static constexpr char digits[] = "0123456789abcdef";
  std::string hex(64, '\0');
  for (size_t i = 0; i < 32; ++i) {
    hex[i * 2] = digits[data[i] >> 4];
    hex[i * 2 + 1] = digits[data[i] & 0x0f];
  }
  return hex;
}

static secp256k1_context *verify_context() {
  static secp256k1_context *ctx =
      secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
  return ctx;
}

static bool signature_verify(const std::vector<uint8_t> &bytes_sig,
                             const std::vector<uint8_t> &bytes_pub,
                             const uint8_t digest[32]) {
  if (bytes_sig.size() != 64 || bytes_pub.size() != 32) {
    return false;
  }
  auto *ctx = verify_context();
  secp256k1_xonly_pubkey pub;
  if (!secp256k1_xonly_pubkey_parse(ctx, &pub, bytes_pub.data())) {
    return false;
  }

  return secp256k1_schnorrsig_verify(ctx, bytes_sig.data(), digest,
#ifdef SECP256K1_SCHNORRSIG_EXTRAPARAMS_INIT
                                     32,
#endif
                                     &pub);
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

  std::string delegation_str;
  delegation_str.reserve(18 + ev.pubkey.size() + conditions.size());
  delegation_str += "nostr:delegation:";
  delegation_str += ev.pubkey;
  delegation_str += ":";
  delegation_str += conditions;

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
