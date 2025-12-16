cmake_minimum_required(VERSION 3.16)
project(Server_v1 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(Server_linux_v1
    Server_linux_v1.cpp
    Server_linux_v1.h
    Data.cpp
    Server_class.cpp
)

# ASIO (header-only)
target_include_directories(Server_linux_v1 PRIVATE
    ${CMAKE_SOURCE_DIR}/Lib/asio-1.36.0/include
)

    find_package(OpenSSL REQUIRED)
    target_link_libraries(Server_linux_v1 PRIVATE OpenSSL::SSL OpenSSL::Crypto pthread)