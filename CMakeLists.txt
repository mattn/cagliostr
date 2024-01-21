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
)

if (CMAKE_COMPILER_IS_GNUCC)
    set(CMAKE_C_FLAGS "${CMAKE_CXX_FLAGS} -iquote ${PROJECT_SOURCE_DIR}/deps/libuv/include")
endif()

add_executable(cagliostr main.cxx deps/matheus28-ws28/src/Server.cpp deps/matheus28-ws28/src/Client.cpp deps/matheus28-ws28/src/base64.cpp)
target_link_libraries(cagliostr crypto)
target_link_libraries(cagliostr ssl)
target_link_libraries(cagliostr uv)
target_link_libraries(cagliostr secp256k1)
