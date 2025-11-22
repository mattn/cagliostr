# syntax=docker/dockerfile:1.4

FROM alpine:3.20 AS build-dev
RUN apk add --no-cache \
    g++ \
    cmake \
    make \
    git \
    sqlite-dev \
    openssl-dev \
    postgresql-dev \
    linux-headers
WORKDIR /usr/src/app
COPY . /usr/src/app
RUN git submodule update --init --recursive --recommend-shallow --depth 1

# patch ws28 library to fix issues
RUN cd deps/matheus28-ws28 && patch -p1 < ../../ws28-fix.patch

RUN mkdir build && cd build && \
    cmake -DCMAKE_BUILD_TYPE=Release .. && \
    make cagliostr
# Verify dynamic linking
RUN ldd build/cagliostr

FROM alpine:3.20 AS build-run
RUN apk add --no-cache \
    libpq \
    openssl \
    sqlite-libs \
    libstdc++ \
    ca-certificates
COPY --from=build-dev /usr/src/app/build/cagliostr /usr/bin/cagliostr
RUN mkdir /data
ENTRYPOINT ["/usr/bin/cagliostr"]
