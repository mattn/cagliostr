cmake_minimum_required(VERSION 2.8)
project(cagliostr)
include(ExternalProject)
include(CheckLibraryExists)

message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")

set(CMAKE_CXX_FLAGS "-O3 -Wall -Wextra")
set(CMAKE_CXX_FLAGS_DEBUG "-g -Wall -Wextra")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -s")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -s")

if (CMAKE_COMPILER_IS_GNUCC)
    set(CMAKE_C_FLAGS "-O2 -g -Wall -Wno-unused-function ${CMAKE_C_FLAGS}")
endif()

include_directories(
    cagliostr
    ${PROJECT_SOURCE_DIR}/deps/dcdpr-libbech32/include
    ${PROJECT_SOURCE_DIR}/deps/matheus28-ws28/src
    ${PROJECT_SOURCE_DIR}/deps/nlohmann-json/include
    ${PROJECT_SOURCE_DIR}/deps/libuv-libuv/include
    ${PROJECT_SOURCE_DIR}/deps/bitcoin-core-libsecp256k1/include
    ${PROJECT_SOURCE_DIR}/deps/gabime-spdlog/include
    )

add_executable(cagliostr main.cxx records.cxx deps/matheus28-ws28/src/Server.cpp deps/matheus28-ws28/src/Client.cpp deps/matheus28-ws28/src/base64.cpp)

set(LIBUV_LIBRARIES ${CMAKE_CURRENT_SOURCE_DIR}/deps/libuv-libuv/build/libuv.a)
add_custom_target(libuv DEPENDS ${LIBUV_LIBRARIES})
add_custom_command(
    OUTPUT ${LIBUV_LIBRARIES}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/deps/libuv-libuv
    COMMAND sh
    ARGS -c 'cmake -B build && cmake --build build -t uv_a'
    )
add_dependencies(cagliostr libuv)
link_directories(${CMAKE_CURRENT_SOURCE_DIR}/deps/libuv-libuv/build)

set(LIBSECP256K1_LIBRARIES ${CMAKE_CURRENT_SOURCE_DIR}/deps/bitcoin-core-libsecp256k1/build/src/libsecp256k1.a)
add_custom_target(libsecp256k1 DEPENDS ${LIBSECP256K1_LIBRARIES})
add_custom_command(
    OUTPUT ${LIBSECP256K1_LIBRARIES}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/deps/bitcoin-core-libsecp256k1
    COMMAND sh
    ARGS -c 'cmake -B build  -DBUILD_SHARED_LIBS=off && cmake --build build'
    )
add_dependencies(cagliostr libsecp256k1)
link_directories(${CMAKE_CURRENT_SOURCE_DIR}/deps/bitcoin-core-libsecp256k1/build/src)

set(LIBSPDLOG_LIBRARIES ${CMAKE_CURRENT_SOURCE_DIR}/deps/gabime-spdlog/build/libspdlog.a)
add_custom_target(libspdlog DEPENDS ${LIBSPDLOG_LIBRARIES})
add_custom_command(
    OUTPUT ${LIBSPDLOG_LIBRARIES}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/deps/gabime-spdlog
    COMMAND sh
    ARGS -c 'cmake -B build  -DBUILD_SHARED_LIBS=off && cmake --build build -t spdlog'
    )
add_dependencies(cagliostr libspdlog)
link_directories(${CMAKE_CURRENT_SOURCE_DIR}/deps/gabime-spdlog/build)

target_link_libraries(cagliostr crypto)
target_link_libraries(cagliostr ssl)
target_link_libraries(cagliostr sqlite3)
target_link_libraries(cagliostr ${LIBUV_LIBRARIES})
target_link_libraries(cagliostr ${LIBSECP256K1_LIBRARIES})
target_link_libraries(cagliostr ${LIBSPDLOG_LIBRARIES})
