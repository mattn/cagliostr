# syntax=docker/dockerfile:1.4

FROM debian:bookworm AS build-dev
WORKDIR /usr/src/app
RUN apt update && apt install -y g++ libsqlite3-dev libssl-dev cmake make git
COPY . /usr/src/app
RUN git submodule update --init
RUN mkdir build && cd build && cmake -DCMAKE_BUILD_TYPE=Release .. && make
FROM debian:bookworm AS build-run
RUN apt update && apt install -y libsqlite3-0 libssl3
COPY --link --from=build-dev /usr/src/app/build/cagliostr /usr/bin/cagliostr
COPY --from=build-dev /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
RUN mkdir /data
CMD ["/usr/bin/cagliostr"]
