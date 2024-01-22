cmake_minimum_required(VERSION 2.8)
project(cagliostr)
include(ExternalProject)
include(CheckLibraryExists)

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
    )

add_executable(cagliostr main.cxx deps/matheus28-ws28/src/Server.cpp deps/matheus28-ws28/src/Client.cpp deps/matheus28-ws28/src/base64.cpp)

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

target_link_libraries(cagliostr crypto)
target_link_libraries(cagliostr ssl)
target_link_libraries(cagliostr ${LIBUV_LIBRARIES})
target_link_libraries(cagliostr ${LIBSECP256K1_LIBRARIES})
