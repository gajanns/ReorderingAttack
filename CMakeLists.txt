cmake_minimum_required(VERSION 3.10)
project(ReorderingAttack LANGUAGES C CXX)

# C++ Standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Compiler flags
set(CMAKE_CXX_FLAGS_DEBUG           "-O0 -g -Wall -Wextra -Wpedantic -Werror")
set(CMAKE_CXX_FLAGS_RELEASE         "-O3 -Wall -Wextra -Wpedantic -Werror")
set(CMAKE_CXX_FLAGS_RELWITHDEBINFO  "-O2 -g -Wall -Wextra -Wpedantic -Werror")

# Include directories
include_directories(${PROJECT_SOURCE_DIR}/include)

# Subdirectories
add_subdirectory(src)

# Executables
add_executable(Sample main.cpp)
target_link_libraries(Sample PRIVATE Client)

add_executable(SingleQTrafficGen singleq_traffic_gen.cpp)
target_link_libraries(SingleQTrafficGen PRIVATE PacketBuilder Client)

add_executable(MultiQRSSTrafficGen multiq_rss_traffic_gen.cpp)
target_link_libraries(MultiQRSSTrafficGen PRIVATE PacketBuilder)