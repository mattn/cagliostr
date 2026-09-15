# cagliostr

High performance Nostr Relay written in C++

![cagliostr](cagliostr.png)

## Usage

```
$ ./cagliostr --help
Usage: cagliostr [--help] [--version] [-database DATABASE] [-loglevel LEVEL]

Optional arguments:
  -h, --help          shows help message and exits 
  -v, --version       prints version information and exits 
  -database DATABASE  connection string [default: "./cagliostr.sqlite"]
                      PostgreSQL is used if the value starts with postgres://.
  -loglevel LEVEL     log level [default: "info"]
```

## Running several instances

With `-redis` (or `$REDIS_URL`), every accepted event is published on a Redis
pub/sub channel and delivered by all instances subscribed to it, so clients
connected to different instances see each other's events in real time. The
storage does not have to be shared for this to work.

```
$ ./cagliostr -port 7447 -database a.sqlite -redis redis://localhost:6379 &
$ ./cagliostr -port 7448 -database b.sqlite -redis redis://localhost:6379 &
```

The URL follows [redis-plus-plus](https://github.com/sewenew/redis-plus-plus)
conventions, e.g. `redis://user:password@host:6379/0` or
`unix:///var/run/redis.sock`. Set `REDIS_CHANNEL` (default `cagliostr:events`)
to keep several relays on one Redis apart. The payload is the bare event JSON,
which is what [nostr-relay](https://github.com/mattn/nostr-relay) publishes
too, so both can share a channel.

Without `-redis` nothing changes: events are delivered in-process as before
and no Redis code path is exercised.

## Requirements

* OpenSSL
* libsqlite3
* libpq

## Installation

```
$ git submodule update --init --recursive
$ cmake -B build && cmake --build build
```

## Tests

Run `ctest --test-dir build --output-on-failure` for SQLite tests.
To test PostgreSQL, set `CAGLIOSTR_TEST_POSTGRES_DSN` to a disposable test
database connection string and run the same command. The PostgreSQL tests
truncate the `event` table before each storage test.

## License

MIT

## Author

Yasuhiro Matsumoto (a.k.a. mattn)
