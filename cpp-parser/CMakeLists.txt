cmake_minimum_required(VERSION 3.14)
project(ssh_parser
    VERSION   1.0.0
    LANGUAGES CXX
    DESCRIPTION "High-performance SSH auth.log parser"
)

# ── C++17 required for structured bindings & std::optional ────────────────────
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ── Source files ──────────────────────────────────────────────────────────────
add_executable(ssh_parser
    src/main.cpp
)

# ── Include directories ──────────────────────────────────────────────────────
target_include_directories(ssh_parser PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# ── Threading support (required for std::thread / std::mutex) ────────────────
find_package(Threads REQUIRED)
target_link_libraries(ssh_parser PRIVATE Threads::Threads)

# ── Compiler warnings (strict but not pedantic for beginner-friendliness) ────
target_compile_options(ssh_parser PRIVATE
    -Wall -Wextra -O2
)

# ── Install target ───────────────────────────────────────────────────────────
install(TARGETS ssh_parser DESTINATION bin)
