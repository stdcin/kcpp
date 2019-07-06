cmake_minimum_required(VERSION 3.1.0 FATAL_ERROR)

project(kcpp)
set(CMAKE_CXX_STANDARD 11)

option(KCPP__DISABLE_TCP "disable tcp feature" OFF)
option(KCPP__BUILD_LIBTINS "build custom libtins" ON)
option(KCPP__BUILD_LIBTINS_STATIC "libtins static build" OFF)
option(KCPP__ENABLE_TESTS "build tests" OFF)

if (WIN32)
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
    set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

    # libevent
    set(EVENT__DISABLE_OPENSSL ON CACHE BOOL "disable libevent:openssl" FORCE)
    set(EVENT__DISABLE_BENCHMARK ON CACHE BOOL "disable libevent:benchmark" FORCE)
    set(EVENT__DISABLE_TESTS ON CACHE BOOL "disable libevent:tests" FORCE)
    set(EVENT__DISABLE_REGRESS ON CACHE BOOL "disable libevent:regress" FORCE)
    set(EVENT__DISABLE_SAMPLES ON CACHE BOOL "disable libevent:samples" FORCE)
    add_subdirectory(third_party/libevent)

    # winpcap
    if (NOT KCPP__DISABLE_TCP)
        set(PCAP_ROOT_DIR ${CMAKE_SOURCE_DIR}/third_party/WpdPack)
    endif ()

    # openssl
    set(OPENSSL_USE_STATIC_LIBS FALSE)
endif ()

find_package(OpenSSL REQUIRED)

if (KCPP__DISABLE_TCP)
    add_definitions(-DKCPP_DISABLE_TCP)
endif ()
if ((WIN32 OR KCPP__BUILD_LIBTINS) AND NOT KCPP__DISABLE_TCP)
    set(LIBTINS_BUILD_EXAMPLES OFF CACHE BOOL "disable LIBTINS_BUILD_EXAMPLES" FORCE)
    set(LIBTINS_BUILD_TESTS OFF CACHE BOOL "disable LIBTINS_BUILD_TESTS" FORCE)
    if (KCPP__BUILD_LIBTINS_STATIC)
        set(LIBTINS_BUILD_SHARED OFF CACHE BOOL "libtins static build" FORCE)
    endif ()
    set(LIBTINS_ENABLE_WPA2 OFF CACHE BOOL "disable WPA2" FORCE)
    add_subdirectory(third_party/libtins)
endif ()

if (KCPP__ENABLE_TESTS)
    enable_testing()
    add_subdirectory(test)
    add_subdirectory(third_party/googletest)
endif ()

add_subdirectory(third_party/kcp)
add_subdirectory(src)

