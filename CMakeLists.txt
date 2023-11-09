cmake_minimum_required(VERSION 3.10)
project(dns_poision CXX)

set(CMAKE_CXX_STANDARD 17)

# libTins
set(LIBTINS_ENABLE_CXX11 1)
set(LIBTINS_BUILD_SHARED 0)
set(LIBTINS_ENABLE_ACK_TRACKER 0)
set(LIBTINS_ENABLE_WPA2 0)
set(LIBTINS_ENABLE_DOT11 0)
add_subdirectory(libtins)

# spdlog
add_subdirectory(spdlog)

# dns poision
add_executable(dns_poision main.cpp)
target_link_libraries(dns_poision tins spdlog::spdlog)
target_include_directories(dns_poision PRIVATE libtins/include)