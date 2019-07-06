PROJECT(kcp)
CMAKE_MINIMUM_REQUIRED(VERSION 2.6)

add_library(kcp STATIC ikcp.c)

target_include_directories(kcp PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        )




