cmake_minimum_required(VERSION 3.10)
project(cagliostr)
include(ExternalProject)
include(CheckLibraryExists)

message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")

#set(CMAKE_CXX_STANDARD 20)
#set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "-std=c++20 -Wall -Wextra -pedantic")
set(CMAKE_CXX_FLAGS_DEBUG "-g3 -O0 -pg ${CMAKE_C_FLAGS}")
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -Wall -Wextra ${CMAKE_C_FLAGS}")
set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "-g3 -Og -pg")
set(CMAKE_CXX_FLAGS_MINSIZEREL "-Os -s -DNDEBUG -march=native")

#--------------------------------------------------
# libuv
set(LIBUV_LIBRARIES ${CMAKE_CURRENT_SOURCE_DIR}/deps/libuv-libuv/build/libuv.a)
add_custom_target(libuv DEPENDS ${LIBUV_LIBRARIES})
add_custom_command(
    OUTPUT ${LIBUV_LIBRARIES}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/deps/libuv-libuv
    COMMAND ${CMAKE_COMMAND} -B build -D CMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
    COMMAND ${CMAKE_COMMAND} --build build -t uv_a
)
link_directories(${CMAKE_CURRENT_SOURCE_DIR}/deps/libuv-libuv/build)

#--------------------------------------------------
# libsecp256k1
set(LIBSECP256K1_LIBRARIES ${CMAKE_CURRENT_SOURCE_DIR}/deps/bitcoin-core-libsecp256k1/build/lib/libsecp256k1.a)
add_custom_target(libsecp256k1 DEPENDS ${LIBSECP256K1_LIBRARIES})
#target_compile_definitions(${LIBSECP256K1_LIBRARIES} PRIVATE SECP256K1_STATIC)
add_compile_definitions(SECP256K1_STATIC)
add_custom_command(
    OUTPUT ${LIBSECP256K1_LIBRARIES}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/deps/bitcoin-core-libsecp256k1
    COMMAND ${CMAKE_COMMAND} -B build -D CMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE} -D BUILD_SHARED_LIBS=off -D SECP256K1_ECMULT_WINDOW_SIZE=15
    COMMAND ${CMAKE_COMMAND} --build build -t secp256k1
)
link_directories(${CMAKE_CURRENT_SOURCE_DIR}/deps/bitcoin-core-libsecp256k1/build/src)

#--------------------------------------------------
# libpqxx
add_subdirectory(deps/jtv-libpqxx)
set_target_properties(pqxx PROPERTIES BUILD_SHARED_LIBS OFF)
add_compile_definitions(PQXX_STATIC)

#--------------------------------------------------
# cagliostr-core
set_property(GLOBAL APPEND PROPERTY ADDITIONAL_CLEAN_FILES
    "${CMAKE_CURRENT_SOURCE_DIR}/deps/gabime-spdlog/build/CMakeFiles"
    "${CMAKE_CURRENT_SOURCE_DIR}/deps/gabime-spdlog/build/Makefile"
    "${CMAKE_CURRENT_SOURCE_DIR}/deps/gabime-spdlog/build/cmake_install.cmake"
    "${CMAKE_CURRENT_SOURCE_DIR}/deps/libuv-libuv/build/CMakeFiles"
    "${CMAKE_CURRENT_SOURCE_DIR}/deps/libuv-libuv/build/Makefile"
    "${CMAKE_CURRENT_SOURCE_DIR}/deps/libuv-libuv/build/cmake_install.cmake"
    "${CMAKE_CURRENT_SOURCE_DIR}/deps/bitcoin-core-libsecp256k1/build/CMakeFiles"
    "${CMAKE_CURRENT_SOURCE_DIR}/deps/bitcoin-core-libsecp256k1/build/Makefile"
    "${CMAKE_CURRENT_SOURCE_DIR}/deps/bitcoin-core-libsecp256k1/build/cmake_install.cmake"
    "${CMAKE_CURRENT_SOURCE_DIR}/deps/jtv-libpqxx/build/CMakeFiles"
    "${CMAKE_CURRENT_SOURCE_DIR}/deps/jtv-libpqxx/build/Makefile"
    "${CMAKE_CURRENT_SOURCE_DIR}/deps/jtv-libpqxx/build/cmake_install.cmake"
)

#--------------------------------------------------
# cagliostr-core
set (t_ cagliostr-core)

include_directories(
    ${t_}
    ${PROJECT_SOURCE_DIR}/deps/dcdpr-libbech32/include
    ${PROJECT_SOURCE_DIR}/deps/matheus28-ws28/src
    ${PROJECT_SOURCE_DIR}/deps/nlohmann-json/include
    ${PROJECT_SOURCE_DIR}/deps/libuv-libuv/include
    ${PROJECT_SOURCE_DIR}/deps/bitcoin-core-libsecp256k1/include
    ${PROJECT_SOURCE_DIR}/deps/gabime-spdlog/include
    ${PROJECT_SOURCE_DIR}/deps/p-ranav-argparse/include
)
add_library (${t_} INTERFACE)
add_dependencies(${t_} libuv)
add_dependencies(${t_} libsecp256k1)
add_dependencies(${t_} libspdlog)
target_link_libraries(${t_} INTERFACE crypto)
target_link_libraries(${t_} INTERFACE ssl)
target_link_libraries(${t_} INTERFACE sqlite3)
target_link_libraries(${t_} INTERFACE ${LIBUV_LIBRARIES})
target_link_libraries(${t_} INTERFACE pqxx)
target_link_libraries(${t_} INTERFACE ${LIBSECP256K1_LIBRARIES})
target_link_libraries(${t_} INTERFACE pq)
if (WIN32)
target_link_libraries(${t_} INTERFACE secur32 ws2_32 dbghelp userenv iphlpapi)
endif()
if(MINGW)
    target_link_libraries(${t_} INTERFACE
        pgcommon
        pgport
        intl
    )
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static-libgcc -static-libstdc++")
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -static-libgcc -static-libstdc++")
endif()

#--------------------------------------------------
# cagliostr
set (t_ cagliostr)
add_executable(${t_} main.cxx sqlite3.cxx postgresql.cxx sign.cxx deps/matheus28-ws28/src/Server.cpp deps/matheus28-ws28/src/Client.cpp)
target_link_libraries(${t_} PRIVATE cagliostr-core)

#--------------------------------------------------
# test
set (t_ cagliostr-test)
include_directories(
    ${t_}
    ${PROJECT_SOURCE_DIR}/deps/h2o-picotest
)
add_executable(${t_} test.cxx ${PROJECT_SOURCE_DIR}/deps/h2o-picotest/picotest.c sqlite3.cxx postgresql.cxx sign.cxx)
target_link_libraries(${t_} PRIVATE cagliostr-core)

enable_testing()
add_test(test cagliostr-test)
