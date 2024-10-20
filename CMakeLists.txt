cmake_minimum_required(VERSION 3.10)
project(JWKS_Server_Test)

set(CMAKE_CXX_STANDARD 11)

# Find cpprestsdk
find_package(cpprestsdk REQUIRED)

# Find OpenSSL
find_package(OpenSSL REQUIRED)

# Fetch Catch2
include(FetchContent)
FetchContent_Declare(
    catch2
    GIT_REPOSITORY https://github.com/catchorg/Catch2.git
    GIT_TAG v2.x
)
FetchContent_MakeAvailable(catch2)

# Enable coverage
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} --coverage")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} --coverage")

add_executable(jwks_server_test jwks_server_test.cpp)
target_link_libraries(jwks_server_test Catch2::Catch2 cpprest OpenSSL::SSL OpenSSL::Crypto)

