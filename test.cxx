// clang-format off

#define INITIALIZE_LOGGER

#include <picotest.h>
#undef ok
#define CAGLIOSTR_TEST
#include "cagliostr.hxx"

#include <spdlog/common.h>
#include <spdlog/spdlog.h>

#include <filesystem>
#include <set>
#include <vector>

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

static event_t make_event(const std::string& id, const std::string& pubkey,
                          std::time_t created_at, int kind,
                          std::vector<std::vector<std::string>> tags,
                          const std::string& content) {
  return event_t{
      .id = id,
      .pubkey = pubkey,
      .created_at = created_at,
      .kind = kind,
      .tags = std::move(tags),
      .content = content,
      .sig = std::string(128, '0'),
  };
}

static storage_context_t init_test_storage(const char* path = "test.sqlite") {
  std::filesystem::remove(path);
  storage_context_t storage_ctx;
  storage_context_init_sqlite3(storage_ctx);
  storage_ctx.init(path);
  return storage_ctx;
}

static void test_cagliostr_records() {
  auto storage_ctx = init_test_storage();
  event_t ev;

  ev = string2event(
      R"({"id":"bb97556f36930838b8593b9e3dd130182e77f34ddf6c8e351b41b1753dc2580a","pubkey":"2c7cc62a697ea3a7826521f3fd34f0cb273693cbe5e9310f35449f43622a5cdc","created_at":1706278266,"kind":1,"tags":[["r","https://image.nostr.build/9b882abc8183d79fdda4c5278228a5f1641b78fa457e643532c5e1c2d89ae6f9.jpg#m=image%2Fjpeg\u0026dim=1067x1920\u0026blurhash=%5DN9%25MXON%5EnotWSf5jcWAo4WAk9t8kBogofM_WFR%25WBjvR%24s%3Bjrj%3FogRiahRjWBa%23WTj%5DWUa%7DfRRjWERjWBWVR%25ahWBWBjb\u0026x=fdde40d498de759392222679f0a1166c9d4b4012bc815be385aa3e9bd1a225ed"]],"content":"mattn いすぎじゃない？\nhttps://image.nostr.build/9b882abc8183d79fdda4c5278228a5f1641b78fa457e643532c5e1c2d89ae6f9.jpg#m=image%2Fjpeg\u0026dim=1067x1920\u0026blurhash=%5DN9%25MXON%5EnotWSf5jcWAo4WAk9t8kBogofM_WFR%25WBjvR%24s%3Bjrj%3FogRiahRjWBa%23WTj%5DWUa%7DfRRjWERjWBWVR%25ahWBWBjb\u0026x=fdde40d498de759392222679f0a1166c9d4b4012bc815be385aa3e9bd1a225ed","sig":"757a1864233031b013eef28b4e47e16bfe15055e5488735f869270f4488875aad56399fc2b28468617470698b586ddeff5261e7dc386178817d2ce0d6ea36301"})");

  // tests for insert_record
  _ok(storage_ctx.insert_record(ev), "insert_records should be succeeded");

  _ok(!storage_ctx.insert_record(ev), "duplicated event must be rejected");

  // tests for delete_record_by_id_and_pubkey
  _ok(storage_ctx.delete_record_by_id_and_pubkey("bb97556f36930838b8593b9e3dd130182e77f34ddf6c8e351b41b1753dc2580b", "2c7cc62a697ea3a7826521f3fd34f0cb273693cbe5e9310f35449f43622a5cdc") == 0, "delete_record_by_id_and_pubkey should be failed for invalid id");

  _ok(storage_ctx.delete_record_by_id_and_pubkey("bb97556f36930838b8593b9e3dd130182e77f34ddf6c8e351b41b1753dc2580a", "2c7cc62a697ea3a7826521f3fd34f0cb273693cbe5e9310f35449f43622a5cdc") == 1, "delete_record_by_id_and_pubkey should be succeeded for valid id");

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

static void test_event_json_roundtrip() {
  auto original = make_event(
      "event-json-roundtrip",
      "2c7cc62a697ea3a7826521f3fd34f0cb273693cbe5e9310f35449f43622a5cdc",
      1700000000, 30023,
      {{"d", "article-1"}, {"p", "friend-pubkey"}, {"expiration", "4102444800"}},
      "roundtrip payload");

  nlohmann::json j = original;
  auto restored = j.get<event_t>();

  _ok(restored.id == original.id, "event id survives to_json/from_json");
  _ok(restored.pubkey == original.pubkey,
      "event pubkey survives to_json/from_json");
  _ok(restored.created_at == original.created_at,
      "event created_at survives to_json/from_json");
  _ok(restored.kind == original.kind, "event kind survives to_json/from_json");
  _ok(restored.tags == original.tags, "event tags survive to_json/from_json");
  _ok(restored.content == original.content,
      "event content survives to_json/from_json");
  _ok(restored.sig == original.sig, "event sig survives to_json/from_json");
}

static void test_get_event_by_id() {
  auto storage_ctx = init_test_storage();
  auto inserted = make_event(
      "event-get-1",
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      1700000001, 1, {{"e", "root-event"}}, "fetch me");

  _ok(storage_ctx.insert_record(inserted), "get_event_by_id setup insert");

  auto found = storage_ctx.get_event_by_id(inserted.id);
  _ok(found.has_value(), "get_event_by_id returns inserted event");
  _ok(found->id == inserted.id, "get_event_by_id preserves id");
  _ok(found->pubkey == inserted.pubkey, "get_event_by_id preserves pubkey");
  _ok(found->content == inserted.content, "get_event_by_id preserves content");
  _ok(found->tags == inserted.tags, "get_event_by_id preserves tags");

  auto missing = storage_ctx.get_event_by_id("missing-event-id");
  _ok(!missing.has_value(), "get_event_by_id returns nullopt for missing id");

  storage_ctx.deinit();
}

static void test_send_records_filters() {
  auto storage_ctx = init_test_storage();
  auto pubkey1 =
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  auto pubkey2 =
      "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
  auto now = std::time(nullptr);
  auto ev1 = make_event("event-send-1", pubkey1, 1700000100, 1,
                        {{"p", "friend-1"}, {"d", "article-1"}},
                        "hello 100% match");
  auto ev2 = make_event("event-send-2", pubkey2, 1700000200, 2,
                        {{"p", "friend-2"}, {"d", "article-2"}},
                        "other payload");
  auto expired = make_event("event-send-3", pubkey1, 1700000300, 1,
                            {{"expiration", std::to_string(now - 10)}},
                            "expired payload");

  _ok(storage_ctx.insert_record(ev1), "send_records setup insert ev1");
  _ok(storage_ctx.insert_record(ev2), "send_records setup insert ev2");
  _ok(storage_ctx.insert_record(expired), "send_records setup insert expired");

  std::vector<nlohmann::json> replies;
  auto sender = [&replies](const nlohmann::json& reply) { replies.push_back(reply); };

  filter_t by_id;
  by_id.ids = {ev1.id};
  _ok(storage_ctx.send_records(sender, "sub-id", {by_id}, false),
      "send_records succeeds for id filter");
  _ok(replies.size() == 1, "send_records id filter returns one event");
  _ok(replies[0][0] == "EVENT", "send_records returns EVENT message");
  _ok(replies[0][1] == "sub-id", "send_records includes subscription id");
  _ok(replies[0][2]["id"] == ev1.id, "send_records id filter matches event");
  replies.clear();

  filter_t by_author_kind;
  by_author_kind.authors = {pubkey2};
  by_author_kind.kinds = {2};
  _ok(storage_ctx.send_records(sender, "sub-author-kind", {by_author_kind}, false),
      "send_records succeeds for author and kind filters");
  _ok(replies.size() == 1, "send_records author and kind filters return one event");
  _ok(replies[0][2]["id"] == ev2.id,
      "send_records author and kind filters match expected event");
  replies.clear();

  filter_t by_tag_search;
  by_tag_search.tags = {{"p", "friend-1"}};
  by_tag_search.search = "100%";
  _ok(storage_ctx.send_records(sender, "sub-tag-search", {by_tag_search}, false),
      "send_records succeeds for tag and search filters");
  _ok(replies.size() == 1, "send_records tag and search filters return one event");
  _ok(replies[0][2]["id"] == ev1.id,
      "send_records tag and search filters match expected event");
  replies.clear();

  filter_t by_since_until;
  by_since_until.since = 1700000150;
  by_since_until.until = 1700000250;
  _ok(storage_ctx.send_records(sender, "sub-time-range", {by_since_until}, false),
      "send_records succeeds for since/until filter");
  _ok(replies.size() == 1, "send_records since/until filter returns one event");
  _ok(replies[0][2]["id"] == ev2.id,
      "send_records since/until filter matches expected event");
  replies.clear();

  filter_t visible_only;
  visible_only.until = 1700000250;
  visible_only.limit = 2;
  _ok(storage_ctx.send_records(sender, "sub-visible-limit", {visible_only}, false),
      "send_records succeeds for limit filter over visible rows");
  _ok(replies.size() == 2, "send_records respects limit for visible rows");
  _ok(replies[0][2]["id"] == ev2.id, "send_records orders visible rows by created_at desc");
  _ok(replies[1][2]["id"] == ev1.id, "send_records returns next visible row");
  replies.clear();

  filter_t all_rows;
  all_rows.limit = 10;
  _ok(storage_ctx.send_records(sender, "sub-expiration", {all_rows}, false),
      "send_records succeeds when expired rows are present");
  _ok(replies.size() == 2, "send_records omits expired events from EVENT replies");
  _ok(replies[0][2]["id"] == ev2.id, "send_records still returns newest visible row");
  _ok(replies[1][2]["id"] == ev1.id, "send_records still returns older visible row");
  replies.clear();

  _ok(storage_ctx.send_records(sender, "sub-count", {all_rows}, true),
      "send_records succeeds for count");
  _ok(replies.size() == 1, "send_records count returns one message");
  _ok(replies[0][0] == "COUNT", "send_records count returns COUNT message");
  _ok(replies[0][1] == "sub-count", "send_records count includes subscription id");
  _ok(replies[0][2]["count"] == 3, "send_records count reflects matching rows");

  storage_ctx.deinit();
}

struct and_tags_fixture {
  storage_context_t ctx;
  event_t both_meme_cat;
  event_t only_meme;
  event_t only_cat;
  event_t meme_dog;
  event_t bob_meme_cat;
};

static and_tags_fixture make_and_tags_fixture() {
  and_tags_fixture f{};
  f.ctx = init_test_storage();
  auto alice =
      "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
  auto bob =
      "1111111111111111111111111111111111111111111111111111111111111111";
  f.both_meme_cat = make_event(
      "event-and-1", alice, 1700001000, 1,
      {{"t", "meme"}, {"t", "cat"}, {"p", alice}}, "meme cat by alice");
  f.only_meme = make_event("event-and-2", alice, 1700001001, 1,
                           {{"t", "meme"}, {"p", alice}}, "meme only");
  f.only_cat = make_event("event-and-3", alice, 1700001002, 1,
                          {{"t", "cat"}, {"p", alice}}, "cat only");
  f.meme_dog = make_event("event-and-4", alice, 1700001003, 1,
                          {{"t", "meme"}, {"t", "dog"}, {"p", alice}},
                          "meme dog");
  f.bob_meme_cat = make_event(
      "event-and-5", bob, 1700001004, 1,
      {{"t", "meme"}, {"t", "cat"}, {"p", bob}}, "meme cat by bob");
  _ok(f.ctx.insert_record(f.both_meme_cat), "and_tags fixture insert both_meme_cat");
  _ok(f.ctx.insert_record(f.only_meme), "and_tags fixture insert only_meme");
  _ok(f.ctx.insert_record(f.only_cat), "and_tags fixture insert only_cat");
  _ok(f.ctx.insert_record(f.meme_dog), "and_tags fixture insert meme_dog");
  _ok(f.ctx.insert_record(f.bob_meme_cat), "and_tags fixture insert bob_meme_cat");
  return f;
}

static void test_and_tags_basic_match() {
  auto f = make_and_tags_fixture();
  std::vector<nlohmann::json> replies;
  auto sender = [&replies](const nlohmann::json& reply) { replies.push_back(reply); };

  filter_t flt;
  flt.and_tags = {{"t", "meme", "cat"}};
  _ok(f.ctx.send_records(sender, "sub-and-basic", {flt}, false),
      "send_records succeeds for AND filter");
  _ok(replies.size() == 2,
      "AND filter returns only events carrying every requested value");
  std::set<std::string> ids;
  for (const auto &r : replies) ids.insert(r[2]["id"].get<std::string>());
  _ok(ids.count(f.both_meme_cat.id) == 1,
      "AND filter includes alice's meme+cat event");
  _ok(ids.count(f.bob_meme_cat.id) == 1,
      "AND filter includes bob's meme+cat event");
  _ok(ids.count(f.only_meme.id) == 0, "AND filter excludes meme-only event");
  _ok(ids.count(f.only_cat.id) == 0, "AND filter excludes cat-only event");
  _ok(ids.count(f.meme_dog.id) == 0, "AND filter excludes meme+dog event");

  f.ctx.deinit();
}

static void test_and_tags_no_match() {
  auto f = make_and_tags_fixture();
  std::vector<nlohmann::json> replies;
  auto sender = [&replies](const nlohmann::json& reply) { replies.push_back(reply); };

  filter_t flt;
  flt.and_tags = {{"t", "meme", "unicorn"}};
  _ok(f.ctx.send_records(sender, "sub-and-empty", {flt}, false),
      "send_records succeeds when AND filter matches nothing");
  _ok(replies.empty(), "AND filter with unmet value returns no events");

  f.ctx.deinit();
}

static void test_and_tags_single_value_equivalent_to_or() {
  auto f = make_and_tags_fixture();
  std::vector<nlohmann::json> and_replies;
  std::vector<nlohmann::json> or_replies;
  auto and_sender = [&](const nlohmann::json& r) { and_replies.push_back(r); };
  auto or_sender = [&](const nlohmann::json& r) { or_replies.push_back(r); };

  filter_t and_flt;
  and_flt.and_tags = {{"t", "meme"}};
  filter_t or_flt;
  or_flt.tags = {{"t", "meme"}};

  _ok(f.ctx.send_records(and_sender, "sub-and-single", {and_flt}, false),
      "send_records succeeds for single-value AND filter");
  _ok(f.ctx.send_records(or_sender, "sub-or-single", {or_flt}, false),
      "send_records succeeds for single-value OR filter");
  _ok(and_replies.size() == or_replies.size(),
      "single-value AND matches the same count as single-value OR");

  f.ctx.deinit();
}

static void test_and_tags_or_semantics_unchanged() {
  auto f = make_and_tags_fixture();
  std::vector<nlohmann::json> replies;
  auto sender = [&](const nlohmann::json& r) { replies.push_back(r); };

  filter_t flt;
  flt.tags = {{"t", "meme", "cat"}};
  _ok(f.ctx.send_records(sender, "sub-or-multi", {flt}, false),
      "send_records succeeds for OR tags filter");
  _ok(replies.size() == 5,
      "OR filter still returns every event having at least one value");

  f.ctx.deinit();
}

static void test_and_tags_multiple_keys() {
  auto f = make_and_tags_fixture();
  auto alice =
      "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
  std::vector<nlohmann::json> replies;
  auto sender = [&](const nlohmann::json& r) { replies.push_back(r); };

  filter_t flt;
  flt.and_tags = {{"t", "meme", "cat"}, {"p", alice}};
  _ok(f.ctx.send_records(sender, "sub-and-multi-key", {flt}, false),
      "send_records succeeds for AND filter with multiple tag names");
  _ok(replies.size() == 1,
      "AND across distinct tag names intersects correctly");
  _ok(replies[0][2]["id"] == f.both_meme_cat.id,
      "AND across distinct tag names returns the only event matching all");

  f.ctx.deinit();
}

static void test_and_tags_combined_with_or() {
  auto f = make_and_tags_fixture();
  auto alice =
      "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
  std::vector<nlohmann::json> replies;
  auto sender = [&](const nlohmann::json& r) { replies.push_back(r); };

  filter_t flt;
  flt.and_tags = {{"t", "meme", "cat"}};
  flt.tags = {{"p", alice}};
  _ok(f.ctx.send_records(sender, "sub-and-or", {flt}, false),
      "send_records succeeds for AND combined with OR filter");
  _ok(replies.size() == 1,
      "AND combined with OR narrows to events satisfying both clauses");
  _ok(replies[0][2]["id"] == f.both_meme_cat.id,
      "AND+OR returns the alice meme+cat event");

  f.ctx.deinit();
}

static void test_and_tags_count_query() {
  auto f = make_and_tags_fixture();
  std::vector<nlohmann::json> replies;
  auto sender = [&](const nlohmann::json& r) { replies.push_back(r); };

  filter_t flt;
  flt.and_tags = {{"t", "meme", "cat"}};
  _ok(f.ctx.send_records(sender, "sub-and-count", {flt}, true),
      "send_records succeeds for COUNT with AND filter");
  _ok(replies.size() == 1, "AND COUNT returns one COUNT message");
  _ok(replies[0][0] == "COUNT", "AND COUNT message has COUNT verb");
  _ok(replies[0][2]["count"] == 2,
      "AND COUNT reflects events satisfying every value");

  f.ctx.deinit();
}

static void test_delete_record_by_id_and_kind_and_ptag() {
  auto storage_ctx = init_test_storage();
  auto id = "event-ptag-1";
  auto owner =
      "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
  auto matching = make_event(id, owner, 1700000400, 5, {{"p", "friend-ptag"}},
                             "ptag target");
  auto different_tag =
      make_event("event-ptag-2", owner, 1700000401, 5, {{"p", "other-friend"}},
                 "different ptag");

  _ok(storage_ctx.insert_record(matching),
      "delete_record_by_id_and_kind_and_ptag setup insert matching");
  _ok(storage_ctx.insert_record(different_tag),
      "delete_record_by_id_and_kind_and_ptag setup insert different");

  std::vector<std::string> missing_tag = {"p", "missing-friend"};
  std::vector<std::string> matching_tag = {"p", "friend-ptag"};

  _ok(storage_ctx.delete_record_by_id_and_kind_and_ptag(id, 5, missing_tag) == 0,
      "delete_record_by_id_and_kind_and_ptag ignores non-matching tag");
  _ok(storage_ctx.delete_record_by_id_and_kind_and_ptag(id, 5, matching_tag) == 1,
      "delete_record_by_id_and_kind_and_ptag deletes matching event");
  _ok(!storage_ctx.get_event_by_id(id).has_value(),
      "delete_record_by_id_and_kind_and_ptag removes deleted event");
  _ok(storage_ctx.get_event_by_id(different_tag.id).has_value(),
      "delete_record_by_id_and_kind_and_ptag keeps unrelated event");

  storage_ctx.deinit();
}

static void test_delete_all_events_by_pubkey() {
  auto storage_ctx = init_test_storage();
  auto pubkey =
      "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
  auto target = make_event("event-pubkey-1", pubkey, 1700000500, 1, {},
                           "delete me");
  auto preserve_kind62 =
      make_event("event-pubkey-2", pubkey, 1700000501, 62, {}, "keep me");
  auto preserve_newer =
      make_event("event-pubkey-3", pubkey, 1700000600, 1, {}, "keep newer");
  auto preserve_other_author = make_event(
      "event-pubkey-4",
      "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
      1700000500, 1, {}, "keep other author");

  _ok(storage_ctx.insert_record(target),
      "delete_all_events_by_pubkey setup insert target");
  _ok(storage_ctx.insert_record(preserve_kind62),
      "delete_all_events_by_pubkey setup insert kind62");
  _ok(storage_ctx.insert_record(preserve_newer),
      "delete_all_events_by_pubkey setup insert newer");
  _ok(storage_ctx.insert_record(preserve_other_author),
      "delete_all_events_by_pubkey setup insert other author");

  _ok(storage_ctx.delete_all_events_by_pubkey(pubkey, 1700000550) == 1,
      "delete_all_events_by_pubkey deletes only matching non-kind62 rows");
  _ok(!storage_ctx.get_event_by_id(target.id).has_value(),
      "delete_all_events_by_pubkey removes older matching event");
  _ok(storage_ctx.get_event_by_id(preserve_kind62.id).has_value(),
      "delete_all_events_by_pubkey preserves kind 62");
  _ok(storage_ctx.get_event_by_id(preserve_newer.id).has_value(),
      "delete_all_events_by_pubkey preserves newer events");
  _ok(storage_ctx.get_event_by_id(preserve_other_author.id).has_value(),
      "delete_all_events_by_pubkey preserves other authors");

  storage_ctx.deinit();
}

static void test_sql_injection_protection() {
  _ok(escape_like("x%x") == "x\\%x", "basic percent escape_like");
  _ok(escape_like("abc") == "abc", "no percent remains unchanged");
  _ok(escape_like("%abc") == "\\%abc", "leading percent escape_like");
  _ok(escape_like("abc%") == "abc\\%", "trailing percent escape_like");
  _ok(escape_like("x%y%z") == "x\\%y\\%z", "multiple percents escape_like");
  _ok(escape_like("%%") == "\\%\\%", "consecutive percents escape_like");
  _ok(escape_like("") == "", "empty string unchanged");
  _ok(escape_like("a_b_c") == "a\\_b\\_c", "underscore escape_like");
  _ok(escape_like("100%") == "100\\%", "percent in number context");
  _ok(escape_like("test%x injection") == "test\\%x injection", "injection-like string escape_like percent");
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
  subtest("test_event_json_roundtrip", test_event_json_roundtrip);
  subtest("test_get_event_by_id", test_get_event_by_id);
  subtest("test_send_records_filters", test_send_records_filters);
  subtest("test_and_tags_basic_match", test_and_tags_basic_match);
  subtest("test_and_tags_no_match", test_and_tags_no_match);
  subtest("test_and_tags_single_value_equivalent_to_or",
          test_and_tags_single_value_equivalent_to_or);
  subtest("test_and_tags_or_semantics_unchanged",
          test_and_tags_or_semantics_unchanged);
  subtest("test_and_tags_multiple_keys", test_and_tags_multiple_keys);
  subtest("test_and_tags_combined_with_or", test_and_tags_combined_with_or);
  subtest("test_and_tags_count_query", test_and_tags_count_query);
  subtest("test_delete_record_by_id_and_kind_and_ptag",
          test_delete_record_by_id_and_kind_and_ptag);
  subtest("test_delete_all_events_by_pubkey", test_delete_all_events_by_pubkey);
  subtest("test_cagliostr_sign", test_cagliostr_sign);
  subtest("test_sql_injection_protection", test_sql_injection_protection);
  return done_testing();
}
