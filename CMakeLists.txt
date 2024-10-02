cmake_minimum_required(VERSION 3.5.0)
project(base VERSION 0.1.0 LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 20)

find_package(MbedTLS CONFIG REQUIRED)
find_package(Qt6 CONFIG REQUIRED COMPONENTS Core)
find_package(spdlog CONFIG REQUIRED)
find_package(minhook CONFIG REQUIRED)

add_library(base STATIC
    xlog.h xlog.cpp
    filehelper_chacha.h filehelper_chacha.cpp
    daily_filechacha_sink.h
    windebug_sink.h
    qjson_helper.h
    exceptiondump.h exceptiondump.cpp
    stacktrace_win.h
    qt_threadpool.h
    boringssl/target.h boringssl/curve25519.h
    boringssl/crypto/curve25519/curve25519.c boringssl/crypto/curve25519/curve25519_64_adx.c
    boringssl/crypto/curve25519/curve25519_tables.h boringssl/crypto/curve25519/internal.h boringssl/crypto/internal.h
)

target_link_libraries(base PUBLIC
    MbedTLS::mbedcrypto
    Qt6::Core
    spdlog::spdlog_header_only
    minhook::minhook
)

if(OPENSSL_NO_ASM)
  add_definitions(-DOPENSSL_NO_ASM)
endif()
