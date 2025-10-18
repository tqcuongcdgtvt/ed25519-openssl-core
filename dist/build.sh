#!/bin/bash

# build.sh - Tự động build thư viện PKI và test
# Tác giả: [Your Name]
# Phiên bản: 1.0.0

set -e  # Thoát ngay nếu có lỗi

echo "=== Build Script for PKI Library ==="
echo "Dependencies: CMake, OpenSSL (libssl-dev)"
echo ""

# Kiểm tra phụ thuộc
if ! command -v cmake &> /dev/null; then
    echo "Error: CMake not found. Install with 'sudo apt install cmake'."
    exit 1
fi

if ! pkg-config --exists openssl; then
    echo "Error: OpenSSL not found. Install with 'sudo apt install libssl-dev'."
    exit 1
fi

echo "Dependencies OK."

# Tạo thư mục build nếu chưa có
if [ ! -d "build" ]; then
    mkdir build
fi

cd build

# Cấu hình CMake
echo "Configuring with CMake..."
cmake ..

# Build
echo "Building..."
make -j$(nproc)  # Sử dụng tất cả CPU cores để nhanh hơn

# Kiểm tra thư viện được tạo
if [ -f "libscrypt_crypto_static.a" ]; then
    echo "Static library created: libscrypt_crypto_static.a"
fi

if [ -f "libscrypt_crypto.so" ]; then
    echo "Shared library created: libscrypt_crypto.so"
fi

# Tạo thư mục dist nếu chưa có
if [ ! -d "../dist" ]; then
    mkdir ../dist
fi

# Sao chép file cần thiết vào dist
cp libscrypt_crypto_static.a ../dist/ 2>/dev/null || echo "No static library"
cp libscrypt_crypto.so ../dist/ 2>/dev/null || echo "No shared library"
cp ../include/scrypt.h ../dist/
cp ../examples/main.c ../dist/example.c
cp ../README.md ../dist/ 2>/dev/null || echo "No README.md"

echo ""
echo "=== Build Success! ==="
echo "Files in dist/: libscrypt_crypto_static.a, libscrypt_crypto.so, scrypt.h, example.c"
echo "To run demo: ./run_demo"
echo "To test: ./test_scrypt, ./boundary_test, ./interoperability_test"
echo "To install: sudo make install"
echo ""

# Tùy chọn: Chạy test nhanh
echo "Running quick test (optional)..."
./run_demo

exit 0
