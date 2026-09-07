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
