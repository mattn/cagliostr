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
  -loglevel LEVEL     log level [default: "info"]
```

## Requirements

* OpenSSL
* libsqlite3

## Installation

```
$ git submodule update --init --recursive
$ cmake -B build && cmake --build build
```

## License

MIT

## Author

Yasuhiro Matsumoto (a.k.a. mattn)
