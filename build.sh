#!/bin/bash

# Build script for phurtimAnalyzer cross-platform binaries
# Creates Linux, Windows, and macOS binaries in bin/ directory

echo "Building phurtimAnalyzer for multiple platforms..."

# Create bin directory if it doesn't exist
mkdir -p bin

# Clean previous builds
echo "Cleaning previous builds..."
rm -f bin/phurtimAnalyzer-*

# Build for Linux (64-bit)
echo "Building Linux binary..."
GOOS=linux GOARCH=amd64 go build -o bin/phurtimAnalyzer-linux main.go
if [ $? -eq 0 ]; then
    echo "✓ Linux binary created: bin/phurtimAnalyzer-linux"
else
    echo "✗ Failed to build Linux binary"
    exit 1
fi

# Build for Windows (64-bit)
echo "Building Windows binary..."
GOOS=windows GOARCH=amd64 go build -o bin/phurtimAnalyzer-windows.exe main.go
if [ $? -eq 0 ]; then
    echo "✓ Windows binary created: bin/phurtimAnalyzer-windows.exe"
else
    echo "✗ Failed to build Windows binary"
    exit 1
fi

# Build for macOS (64-bit)
echo "Building macOS binary..."
GOOS=darwin GOARCH=amd64 go build -o bin/phurtimAnalyzer-macos main.go
if [ $? -eq 0 ]; then
    echo "✓ macOS binary created: bin/phurtimAnalyzer-macos"
else
    echo "✗ Failed to build macOS binary"
    exit 1
fi

# Show build results
echo ""
echo "Build complete! Binaries created:"
ls -lh bin/phurtimAnalyzer-*

echo ""
echo "Usage examples:"
echo "  Linux:   ./bin/phurtimAnalyzer-linux passwords.txt ./output 5 2 500"
echo "  Windows: bin/phurtimAnalyzer-windows.exe passwords.txt ./output 5 2 500"
echo "  macOS:   ./bin/phurtimAnalyzer-macos passwords.txt ./output 5 2 500"