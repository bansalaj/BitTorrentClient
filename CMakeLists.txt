cmake_minimum_required(VERSION 3.13)
project(bittorrent-starter-cpp)
set(CMAKE_CXX_STANDARD 20) # Enable the C++20 standard
set(CMAKE_BUILD_TYPE Debug)
# Find the OpenSSL package
find_package(OpenSSL REQUIRED)
find_package(CURL REQUIRED)
set(SOURCE_FILES src/Main.cpp src/lib/nlohmann/json.hpp)
add_executable(bittorrent ${SOURCE_FILES})

# Link OpenSSL to your executable
target_link_libraries(bittorrent OpenSSL::SSL OpenSSL::Crypto)
target_link_libraries(bittorrent CURL::libcurl)
