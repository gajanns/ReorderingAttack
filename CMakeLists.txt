cmake_minimum_required(VERSION 3.10.0)
project(ReorderingAttack LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Set the output directory for the compiled binaries
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Compiler Flags
set(CMAKE_CXX_FLAGS_DEBUG "-O0 -g -Wall -Wextra -Wpedantic -Werror")
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -Wall -Wextra -Wpedantic -Werror")
set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "-O2 -g -Wall -Wextra -Wpedantic -Werror")


# Header files
include_directories(${PROJECT_SOURCE_DIR}/include)
add_subdirectory(src)

add_executable(ReorderingAttack main.cpp)
target_link_libraries(ReorderingAttack Client)