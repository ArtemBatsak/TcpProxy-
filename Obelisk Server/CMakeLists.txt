cmake_minimum_required(VERSION 3.16)
project(ObeliskServer LANGUAGES CXX)


set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(SRC_DIR ${CMAKE_SOURCE_DIR}/src)
set(LIB_DIR ${CMAKE_SOURCE_DIR}/Lib)


set(SOURCES
    ${SRC_DIR}/main.cpp
    ${SRC_DIR}/manager/Data.cpp
    ${SRC_DIR}/server/Server_class.cpp
    ${SRC_DIR}/tls/tls_session.cpp
)

add_executable(ObeliskServer ${SOURCES})

target_include_directories(ObeliskServer PRIVATE
    ${SRC_DIR}
    ${SRC_DIR}/manager
    ${SRC_DIR}/server
    ${SRC_DIR}/tls
)

if(WIN32)
    # Windows include & libs
    target_include_directories(ObeliskServer PRIVATE
        ${LIB_DIR}/asio-1.36.0/include
        ${LIB_DIR}/openssl/include
    )
    target_link_libraries(ObeliskServer PRIVATE
        ${LIB_DIR}/openssl/lib/ssl.lib
        ${LIB_DIR}/openssl/lib/crypto.lib
    )
else()
    # Linux include & libs
    find_path(ASIO_INCLUDE_DIR asio.hpp)
    if(NOT ASIO_INCLUDE_DIR)
        set(ASIO_INCLUDE_DIR ${LIB_DIR}/asio-1.36.0/include)
    endif()
    target_include_directories(ObeliskServer PRIVATE ${ASIO_INCLUDE_DIR})

    find_package(OpenSSL REQUIRED)
    target_include_directories(ObeliskServer PRIVATE ${OPENSSL_INCLUDE_DIR})
    target_link_libraries(ObeliskServer PRIVATE OpenSSL::SSL OpenSSL::Crypto pthread)
endif()


if(MSVC)
    target_compile_options(ObeliskServer PRIVATE /W4 /permissive-)
else()
    target_compile_options(ObeliskServer PRIVATE -Wall -Wextra -Wpedantic -pthread)
endif()

