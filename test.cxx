// clang-format off

#define INITIALIZE_LOGGER

#include <picotest.h>
#undef ok
#define CAGLIOSTR_TEST
#include "cagliostr.hxx"

#include <spdlog/common.h>
#include <spdlog/spdlog.h>

#include <filesystem>

static event_t string2event(const std::string& string) {
  auto ej = nlohmann::json::parse(string);
  event_t ev;
  ev.id = ej["id"];
  ev.pubkey = ej["pubkey"];
  ev.content = ej["content"];
  ev.created_at = ej["created_at"];
  ev.kind = ej["kind"];
  ev.tags = ej["tags"];
  ev.sig = ej["sig"];
  return ev;
}

static void test_cagliostr_records() {
  std::filesystem::remove("test.sqlite");

  storage_context_t storage_ctx;
  storage_context_init_sqlite3(storage_ctx);
  storage_ctx.init("test.sqlite");
  event_t ev;

  ev = string2event(
      R"({"id":"bb97556f36930838b8593b9e3dd130182e77f34ddf6c8e351b41b1753dc2580a","pubkey":"2c7cc62a697ea3a7826521f3fd34f0cb273693cbe5e9310f35449f43622a5cdc","created_at":1706278266,"kind":1,"tags":[["r","https://image.nostr.build/9b882abc8183d79fdda4c5278228a5f1641b78fa457e643532c5e1c2d89ae6f9.jpg#m=image%2Fjpeg\u0026dim=1067x1920\u0026blurhash=%5DN9%25MXON%5EnotWSf5jcWAo4WAk9t8kBogofM_WFR%25WBjvR%24s%3Bjrj%3FogRiahRjWBa%23WTj%5DWUa%7DfRRjWERjWBWVR%25ahWBWBjb\u0026x=fdde40d498de759392222679f0a1166c9d4b4012bc815be385aa3e9bd1a225ed"]],"content":"mattn いすぎじゃない？\nhttps://image.nostr.build/9b882abc8183d79fdda4c5278228a5f1641b78fa457e643532c5e1c2d89ae6f9.jpg#m=image%2Fjpeg\u0026dim=1067x1920\u0026blurhash=%5DN9%25MXON%5EnotWSf5jcWAo4WAk9t8kBogofM_WFR%25WBjvR%24s%3Bjrj%3FogRiahRjWBa%23WTj%5DWUa%7DfRRjWERjWBWVR%25ahWBWBjb\u0026x=fdde40d498de759392222679f0a1166c9d4b4012bc815be385aa3e9bd1a225ed","sig":"757a1864233031b013eef28b4e47e16bfe15055e5488735f869270f4488875aad56399fc2b28468617470698b586ddeff5261e7dc386178817d2ce0d6ea36301"})");

  // tests for insert_record
  _ok(storage_ctx.insert_record(ev), "insert_records should be succeeded");

  _ok(!storage_ctx.insert_record(ev), "duplicated event must be rejected");

  // tests for delete_record_by_id
  _ok(storage_ctx.delete_record_by_id("bb97556f36930838b8593b9e3dd130182e77f34ddf6c8e351b41b1753dc2580b") == 0, "delete_record_by_id should be failed for invalid id");

  _ok(storage_ctx.delete_record_by_id("bb97556f36930838b8593b9e3dd130182e77f34ddf6c8e351b41b1753dc2580a") == 1, "delete_record_by_id should be succeeded for valid id");

  // tests for delete_record_by_kind_and_pubkey
  _ok(storage_ctx.insert_record(ev), "insert_records should be succeeded");

  _ok(storage_ctx.delete_record_by_kind_and_pubkey(0, "2c7cc62a697ea3a7826521f3fd34f0cb273693cbe5e9310f35449f43622a5cdc", 1721057587) == 0, "delete_record_by_kind_and_pubkey should be failed for invalid kind");

  _ok(storage_ctx.delete_record_by_kind_and_pubkey(1, "2c7cc62a697ea3a7826521f3fd34f0cb273693cbe5e9310f35449f43622a5cdd", 1721057587) == 0, "delete_record_by_kind_and_pubkey should be failed for invalid pubkey");

  _ok(storage_ctx.delete_record_by_kind_and_pubkey(1, "2c7cc62a697ea3a7826521f3fd34f0cb273693cbe5e9310f35449f43622a5cdc", 1721057587) == 1, "delete_record_by_kind_and_pubkey should be succeeded for valid kind and pubkey");

  // tests for delete_record_by_kind_and_pubkey_and_dtag
  ev = string2event(R"({"id":"60a2ad094a92a2fc6619ef7b0e489a316868974647dd4853a3732029b95c93f0","pubkey":"2c7cc62a697ea3a7826521f3fd34f0cb273693cbe5e9310f35449f43622a5cdc","created_at":1705420612,"kind":30023,"tags":[["r","https://nwc.getalby.com/apps/new?c=Algia"],["r","http://myproxy.example.com:8080"],["d","algia-article-test"],["title","Algia Article Test"],["summary","This is a test"],["published_at","1705420612"],["a","30023:2c7cc62a697ea3a7826521f3fd34f0cb273693cbe5e9310f35449f43622a5cdc:algia-article-test","wss://yabu.me"]],"content":"# algia\n\nnostr CLI client written in Go\n\n## Usage\n\n```\nNAME:\n   algia - A cli application for nostr\n\nUSAGE:\n   algia [global options] command [command options] [arguments...]\n\nDESCRIPTION:\n   A cli application for nostr\n\nCOMMANDS:\n   timeline, tl  show timeline\n   stream        show stream\n   post, n       post new note\n   reply, r      reply to the note\n   repost, b     repost the note\n   unrepost, B   unrepost the note\n   like, l       like the note\n   unlike, L     unlike the note\n   delete, d     delete the note\n   search, s     search notes\n   dm-list       show DM list\n   dm-timeline   show DM timeline\n   dm-post       post new note\n   profile       show profile\n   powa          post ぽわ〜\n   puru          post ぷる\n   zap           zap note1\n   version       show version\n   help, h       Shows a list of commands or help for one command\n\nGLOBAL OPTIONS:\n   -a value        profile name\n   --relays value  relays\n   -V              verbose (default: false)\n   --help, -h      show help\n```\n\n## Installation\n\nDownload binary from Release page.\n\nOr install with go install command.\n```\ngo install github.com/mattn/algia@latest\n```\n\n## Configuration\n\nMinimal configuration. Need to be at ~/.config/algia/config.json\n\n```json\n{\n  \"relays\": {\n    \"wss://relay-jp.nostr.wirednet.jp\": {\n      \"read\": true,\n      \"write\": true,\n      \"search\": false\n    }\n  },\n  \"privatekey\": \"nsecXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\"\n}\n```\n\nIf you want to zap via Nostr Wallet Connect, please add `nwc-pub` and `nwc-uri` which are provided from \u003chttps://nwc.getalby.com/apps/new?c=Algia\u003e\n\n```json\n{\n  \"relays\": {\n   ...\n  },\n  \"privatekey\": \"nsecXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\",\n  \"nwc-uri\": \"nostr+walletconnect://xxxxx\",\n  \"nwc-pub\": \"xxxxxxxxxxxxxxxxxxxxxxx\"\n}\n```\n\n## TODO\n\n* [x] like\n* [x] repost\n* [x] zap\n* [x] upload images\n\n## FAQ\n\nDo you use proxy? then set environment variable `HTTP_PROXY` like below.\n\n    HTTP_PROXY=http://myproxy.example.com:8080\n\n## License\n\nMIT\n\n## Author\n\nYasuhiro Matsumoto (a.k.a. mattn)\n","sig":"802600cdd86e3d21435832307a0f01da8e031060880c0aa6d7f6338e17202b34e2eba6bab2c8acf316ff78c1b2489d38f02eaea6da892de31448af4875e503f6"})");

  _ok(storage_ctx.insert_record(ev), "insert_records should be succeeded");

  std::vector<std::string> valid_dtag = {"d", "algia-article-test"};
  std::vector<std::string> invalid_dtag = {"d", "algia-article-test_"};

  _ok(storage_ctx.delete_record_by_kind_and_pubkey_and_dtag(30022, "2c7cc62a697ea3a7826521f3fd34f0cb273693cbe5e9310f35449f43622a5cdc", valid_dtag, 1721057587) == 0, "delete_record_by_kind_and_pubkey_and_dtag should be failed for invalid kind");

  _ok(storage_ctx.delete_record_by_kind_and_pubkey_and_dtag(30023, "2c7cc62a697ea3a7826521f3fd34f0cb273693cbe5e9310f35449f43622a5cdd", valid_dtag, 1721057587) == 0, "delete_record_by_kind_and_pubkey_and_dtag should be failed for invalid pubkey");

  _ok(storage_ctx.delete_record_by_kind_and_pubkey_and_dtag(30023, "2c7cc62a697ea3a7826521f3fd34f0cb273693cbe5e9310f35449f43622a5cdc", invalid_dtag, 1721057587) == 0, "delete_record_by_kind_and_pubkey_and_dtag should be failed for invalid dtag");

  _ok(storage_ctx.delete_record_by_kind_and_pubkey_and_dtag(30023, "2c7cc62a697ea3a7826521f3fd34f0cb273693cbe5e9310f35449f43622a5cdc", valid_dtag, 1721057587) == 1, "delete_record_by_kind_and_pubkey_and_dtag should be succeeded for valid kind and pubkey and dtag");

  storage_ctx.deinit();
}

static void test_sql_injection_protection() {
  std::string malicious_input = "1; DROP TABLE event; --";
  std::string escaped_input = escape(malicious_input);
  _ok(escaped_input == "1%; DROP TABLE event; --", "SQL injection protection failed");
  _ok(escaped_input.find("DROP TABLE") != std::string::npos, "SQL injection protection failed");
  _ok(escaped_input.find("'") == std::string::npos, "SQL injection protection failed");
  _ok(escaped_input.find("\\") == std::string::npos, "SQL injection protection failed");
  _ok(escaped_input.find("%") != std::string::npos, "SQL injection protection failed");
  _ok(escaped_input == "1%; DROP TABLE event; --", "SQL injection protection failed");
}

static void test_ip_parsing() {
}

static void test_cagliostr_sign() {
  event_t ev;

  ev = string2event(
      R"({"id":"bb97556f36930838b8593b9e3dd130182e77f34ddf6c8e351b41b1753dc2580a","pubkey":"2c7cc62a697ea3a7826521f3fd34f0cb273693cbe5e9310f35449f43622a5cdc","created_at":1706278266,"kind":1,"tags":[["r","https://image.nostr.build/9b882abc8183d79fdda4c5278228a5f1641b78fa457e643532c5e1c2d89ae6f9.jpg#m=image%2Fjpeg\u0026dim=1067x1920\u0026blurhash=%5DN9%25MXON%5EnotWSf5jcWAo4WAk9t8kBogofM_WFR%25WBjvR%24s%3Bjrj%3FogRiahRjWBa%23WTj%5DWUa%7DfRRjWERjWBWVR%25ahWBWBjb\u0026x=fdde40d498de759392222679f0a1166c9d4b4012bc815be385aa3e9bd1a225ed"]],"content":"mattn いすぎじゃない？\nhttps://image.nostr.build/9b882abc8183d79fdda4c5278228a5f1641b78fa457e643532c5e1c2d89ae6f9.jpg#m=image%2Fjpeg\u0026dim=1067x1920\u0026blurhash=%5DN9%25MXON%5EnotWSf5jcWAo4WAk9t8kBogofM_WFR%25WBjvR%24s%3Bjrj%3FogRiahRjWBa%23WTj%5DWUa%7DfRRjWERjWBWVR%25ahWBWBjb\u0026x=fdde40d498de759392222679f0a1166c9d4b4012bc815be385aa3e9bd1a225ed","sig":"757a1864233031b013eef28b4e47e16bfe15055e5488735f869270f4488875aad56399fc2b28468617470698b586ddeff5261e7dc386178817d2ce0d6ea36301"})");

  _ok(check_event(ev), "check_event should be succeeded for valid sig");

  ev.sig = "757a1864233031b013eef28b4e47e16bfe15055e5488735f869270f4488875aad56399fc2b28468617470698b586ddeff5261e7dc386178817d2ce0d6ea36302";
  _ok(!check_event(ev), "check_event should be failed for invalid sig");
}

int main() {
  spdlog::set_level(spdlog::level::off);

  subtest("test_cagliostr_records", test_cagliostr_records);
  subtest("test_cagliostr_sign", test_cagliostr_sign);
  subtest("test_sql_injection_protection", test_sql_injection_protection);
  subtest("test_ip_parsing", test_ip_parsing);
  return done_testing();
}
