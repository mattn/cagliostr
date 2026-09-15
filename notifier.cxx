#include "cagliostr.hxx"

#include <atomic>
#include <chrono>
#include <memory>
#include <thread>

#include <sw/redis++/redis++.h>
#include <sw/redis++/redis_uri.h>

// Propagates accepted events between relay instances through a Redis pub/sub
// channel, in the same way as nostr-relay does: every accepted event is
// published on the channel and each subscribed instance delivers it to its
// own clients. The payload is the bare event JSON, so cagliostr and
// nostr-relay instances can share one channel.
//
// Nothing here is touched unless notifier_init() is called, so a relay
// running without Redis keeps its direct in-process delivery as before.

namespace {

struct notifier_t {
  std::unique_ptr<sw::redis::Redis> redis;
  std::string channel;
  std::function<void(const event_t &)> on_event;
  std::atomic<bool> running{false};
  std::thread thread;
};

std::unique_ptr<notifier_t> notifier;

// Interval at which the subscriber wakes up to check the running flag while
// no message arrives, and the default socket timeout for PUBLISH.
constexpr auto socket_timeout = std::chrono::milliseconds(1000);

void subscribe_loop(notifier_t &n) {
  while (n.running) {
    try {
      auto sub = n.redis->subscriber();
      sub.on_message([&n](std::string /*channel*/, std::string msg) {
        try {
          const event_t ev = nlohmann::json::parse(msg);
          // Anyone able to PUBLISH on the channel could inject events, so
          // verify them exactly like those received over WebSocket.
          if (!check_event(ev)) {
            console->warn("!! dropping redis notification with invalid "
                          "id or signature: {}",
                          ev.id);
            return;
          }
          n.on_event(ev);
        } catch (const std::exception &e) {
          console->warn("!! dropping malformed redis notification: {}",
                        e.what());
        }
      });
      sub.subscribe(n.channel);
      console->info("subscribed to redis channel {}", n.channel);
      while (n.running) {
        try {
          sub.consume();
        } catch (const sw::redis::TimeoutError &) {
          // No message within socket_timeout; loop around to re-check the
          // running flag. The subscription itself is still alive.
        }
      }
    } catch (const sw::redis::Error &e) {
      if (!n.running) {
        break;
      }
      console->warn("!! redis subscription lost: {} (reconnecting)", e.what());
      std::this_thread::sleep_for(std::chrono::seconds(1));
    }
  }
}

} // namespace

bool notifier_init(const std::string &url, const std::string &channel,
                   std::function<void(const event_t &)> on_event) {
  try {
    sw::redis::Uri uri(url);
    auto opts = uri.connection_options();
    if (opts.socket_timeout.count() == 0) {
      opts.socket_timeout = socket_timeout;
    }
    if (opts.connect_timeout.count() == 0) {
      opts.connect_timeout = socket_timeout;
    }
    auto n = std::make_unique<notifier_t>();
    n->redis =
        std::make_unique<sw::redis::Redis>(opts, uri.connection_pool_options());
    n->channel = channel;
    n->on_event = std::move(on_event);
    n->running = true;
    n->thread = std::thread(subscribe_loop, std::ref(*n));
    notifier = std::move(n);
    return true;
  } catch (const std::exception &e) {
    console->error("!! invalid redis URL: {}", e.what());
    return false;
  }
}

void notifier_deinit() {
  if (!notifier) {
    return;
  }
  notifier->running = false;
  if (notifier->thread.joinable()) {
    notifier->thread.join();
  }
  notifier.reset();
}

bool notifier_enabled() { return notifier != nullptr; }

bool notifier_publish(const event_t &ev) {
  if (!notifier) {
    return false;
  }
  try {
    const nlohmann::json j = ev;
    notifier->redis->publish(notifier->channel, j.dump());
    return true;
  } catch (const sw::redis::Error &e) {
    console->warn("!! failed to publish event to redis: {}", e.what());
    return false;
  }
}
