# syntax=docker/dockerfile:1.4

FROM debian:trixie-slim AS build-dev
WORKDIR /usr/src/app
RUN apt update && apt install -y g++ libsqlite3-dev libssl-dev cmake make git
COPY . /usr/src/app
RUN git submodule update --init --recursive --recommend-shallow --depth 1
RUN mkdir build && cd build && cmake -DCMAKE_BUILD_TYPE=Release .. && make cagliostr
FROM debian:trixie-slim AS build-run
RUN apt update && apt install -y libsqlite3-0 libssl3 libtcmalloc-minimal4 && apt clean
COPY --link --from=build-dev /usr/src/app/build/cagliostr /usr/bin/cagliostr
COPY --from=build-dev /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
RUN mkdir /data
ENV LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libtcmalloc_minimal.so.4
ENTRYPOINT ["/usr/bin/cagliostr"]
