cmake_minimum_required(VERSION 3.16)
project(ObeliskServer LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(SRC_DIR ${CMAKE_SOURCE_DIR}/src)
set(LIB_DIR ${CMAKE_SOURCE_DIR}/Lib)

set(SOURCES
    ${SRC_DIR}/main.cpp
    ${SRC_DIR}/server/Server_class.cpp
)

add_executable(PhantomgreyServer ${SOURCES})

target_include_directories(PhantomgreyServer PRIVATE
    ${SRC_DIR}
    ${SRC_DIR}/server
)

if(WIN32)
    target_include_directories(PhantomgreyServer PRIVATE
        ${LIB_DIR}/asio-1.36.0/include
        ${LIB_DIR}/OpenSSL/include
    )

    target_link_libraries(PhantomgreyServer PRIVATE
        ${LIB_DIR}/OpenSSL/lib/libssl.lib
        ${LIB_DIR}/OpenSSL/lib/libcrypto.lib
        ws2_32
    )
else()
    find_package(OpenSSL REQUIRED)
    find_path(ASIO_INCLUDE_DIR asio.hpp)

    target_include_directories(PhantomgreyServer PRIVATE
        ${ASIO_INCLUDE_DIR}
        ${OPENSSL_INCLUDE_DIR}
    )

    target_link_libraries(PhantomgreyServer PRIVATE
        OpenSSL::SSL
        OpenSSL::Crypto
        pthread
    )
endif()

if(MSVC)
    target_compile_options(PhantomgreyServer PRIVATE /W4 /permissive-)
else()
    target_compile_options(PhantomgreyServer PRIVATE -Wall -Wextra -Wpedantic)
endif()
