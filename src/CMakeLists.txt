INCLUDE(TestBigEndian)
TEST_BIG_ENDIAN(IS_BIG_ENDIAN)

set(SOURCES kcp.cpp zf_log.c utils.cpp stream.cpp
        sock_address.cpp session.cpp crypto.cpp
        udp_layer.cpp trans_layer.cpp
        frame.cpp config_t.cpp)
if (NOT KCPP__DISABLE_TCP)
    set(SOURCES ${SOURCES} tcp_layer.cpp)
endif ()

add_executable(kcpp_server ${SOURCES} server.cpp)
add_executable(kcpp_local ${SOURCES} local.cpp)

# zf_log mesage ctx
add_definitions("-DZF_LOG_MESSAGE_CTX_FORMAT=(HOUR, S(\":\"), MINUTE, S(\":\"), SECOND, S(\".\"), MILLISECOND, S(ZF_LOG_DEF_DELIMITER), LEVEL, S(ZF_LOG_DEF_DELIMITER))")
# zf_log source location format
add_definitions("-DZF_LOG_MESSAGE_SRC_FORMAT=(FILENAME, S(\":\"), FILELINE, S(\" > \"))")

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../third_party/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../third_party/libtins/include)
include_directories(${PCAP_INCLUDE_DIR})

set_property(TARGET kcpp_server PROPERTY C_STANDARD 11)
set_property(TARGET kcpp_local PROPERTY C_STANDARD 11)

if (UNIX)
    set(DEP_LIBS kcp event pthread event_pthreads OpenSSL::Crypto)
    if (NOT KCPP__DISABLE_TCP)
        set(DEP_LIBS ${DEP_LIBS} tins)
    endif ()
elseif (WIN32)
    include_directories(${LIBEVENT_INCLUDE_DIRS})
    add_definitions(-DNOMINMAX)
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)

    if (NOT (MSVC_VERSION LESS 1900))
        # https://github.com/pocoproject/poco/commit/50ae257a52065c222e0e57e19dad3eadb2333389
    endif ()

    set(DEP_LIBS kcp event_core OpenSSL::Crypto)
    if (NOT KCPP__DISABLE_TCP)
        set(DEP_LIBS ${DEP_LIBS} tins)
    endif ()
endif ()

target_link_libraries(kcpp_server ${DEP_LIBS})
target_link_libraries(kcpp_local ${DEP_LIBS})

install (TARGETS kcpp_server kcpp_local DESTINATION bin)