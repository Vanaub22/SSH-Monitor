#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# build-parser.sh – Compile the C++ SSH parser for the host machine
#
# This script compiles the SSH parser using the C++ compiler on the host
# (clang++ or g++), avoiding the need for cmake or Docker to compile.
#
# The compiled binary will be placed at cpp-parser/ssh_parser
#
# Usage:
#   ./scripts/build-parser.sh          # Uses clang++ (preferred)
#   CC=g++ ./scripts/build-parser.sh   # Force use of g++
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

# Detect the directory this script is in
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
PARSER_DIR="$PROJECT_ROOT/cpp-parser"

echo "╔══════════════════════════════════════════════════╗"
echo "║  SSH Parser Compiler                             ║"
echo "╠══════════════════════════════════════════════════╣"
echo "║  Project root:  $PROJECT_ROOT"
echo "║  Parser dir:    $PARSER_DIR"
echo "╚══════════════════════════════════════════════════╝"
echo ""

# Detect C++ compiler
CXX="${CXX:-clang++}"
if ! command -v "$CXX" &> /dev/null; then
    echo "⚠  $CXX not found, trying g++..."
    CXX="g++"
    if ! command -v "$CXX" &> /dev/null; then
        echo "✗ ERROR: Neither clang++ nor g++ found"
        echo "  Please install Xcode Command Line Tools (macOS) or build-essential (Linux)"
        exit 1
    fi
fi

echo "Using C++ compiler: $CXX"
echo ""

# Compile
echo "Compiling ssh_parser..."
cd "$PARSER_DIR"

"$CXX" \
    -std=c++17 \
    -O2 \
    -Wall -Wextra \
    -I./include \
    -pthread \
    src/main.cpp \
    -o ./ssh_parser

echo "✓ Compilation successful"
echo ""
echo "Binary location: $PARSER_DIR/ssh_parser"
echo "Binary size:     $(ls -lh ./ssh_parser | awk '{print $5}')"
echo ""
echo "To run the parser:"
echo "  $PARSER_DIR/ssh_parser --log /var/log/system.log --out ./shared/ssh_metrics.json"
