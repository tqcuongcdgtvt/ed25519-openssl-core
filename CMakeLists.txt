cmake_minimum_required(VERSION 3.28)
if(COMMAND cmake_policy)
  cmake_policy(SET CMP0003 NEW)
endif()

project(PKI C CXX)

# Tìm OpenSSL
find_package(OpenSSL REQUIRED COMPONENTS Crypto)

# Tìm Check
find_package(PkgConfig REQUIRED)
pkg_check_modules(CHECK REQUIRED check)

# Tìm libsodium
find_library(SODIUM_LIBRARY NAMES sodium)
if (NOT SODIUM_LIBRARY)
    message(WARNING "libsodium not found. Please install libsodium-dev for interoperability tests.")
endif()

# FetchContent cho googletest (comment vì không dùng)
include(FetchContent)
FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.tar.gz
)
# FetchContent_MakeAvailable(googletest) không cần nếu không dùng gtest

# Include directories
include_directories(${OPENSSL_INCLUDE_DIR} ${CHECK_INCLUDE_DIRS} ${CMAKE_CURRENT_SOURCE_DIR}/include)

# Tạo thư viện tĩnh
add_library(scrypt_crypto_static STATIC
    src/scrypt.c
    src/backend_openssl.c
)
target_include_directories(scrypt_crypto_static PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(scrypt_crypto_static PRIVATE OpenSSL::Crypto)

# Tạo thư viện động
add_library(scrypt_crypto SHARED
    src/scrypt.c
    src/backend_openssl.c
)
target_include_directories(scrypt_crypto PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(scrypt_crypto PRIVATE OpenSSL::Crypto)

# Tạo executable run_demo
add_executable(run_demo examples/main.c)
# Có thể chọn link với tĩnh hoặc động tùy ý
target_link_libraries(run_demo PRIVATE scrypt_crypto_static) # Hoặc scrypt_crypto

# Tạo executable test_scrypt
add_executable(test_scrypt src/test_scrypt.c)
target_link_libraries(test_scrypt PRIVATE scrypt_crypto_static ${CHECK_LIBRARIES})

# Tạo executable boundary_test
add_executable(boundary_test tests/boundary_test.c)
target_link_libraries(boundary_test PRIVATE scrypt_crypto_static ${CHECK_LIBRARIES})

# Tạo executable interoperability_test
add_executable(interoperability_test tests/interoperability_test.c)
target_link_libraries(interoperability_test PRIVATE scrypt_crypto_static ${CHECK_LIBRARIES} ${SODIUM_LIBRARY})

set(CMAKE_BUILD_TYPE Debug)

# Tạo executable memory_leak_test
add_executable(memory_leak_test tests/memory_leak_test.c)
target_link_libraries(memory_leak_test PRIVATE scrypt_crypto_static ${CHECK_LIBRARIES})

# THÊM MỚI: Thread safety test
add_executable(thread_safety_test tests/thread_safety_test.c)
target_link_libraries(thread_safety_test PRIVATE scrypt_crypto_static ${CHECK_LIBRARIES})
target_compile_options(thread_safety_test PRIVATE -pthread)
target_link_options(thread_safety_test PRIVATE -pthread)

# THÊM MỚI: Benchmark test
add_executable(benchmark_test tests/benchmark_test.c)
target_link_libraries(benchmark_test PRIVATE scrypt_crypto_static ${CHECK_LIBRARIES})
target_compile_options(benchmark_test PRIVATE -pthread)
target_link_options(benchmark_test PRIVATE -pthread)

# Cài đặt thư viện và header
install(TARGETS scrypt_crypto_static scrypt_crypto
        ARCHIVE DESTINATION lib  # Cho thư viện tĩnh
        LIBRARY DESTINATION lib # Cho thư viện động
)
install(FILES include/scrypt.h DESTINATION include)

# (Tùy chọn) Thêm CPack để tạo gói phân phối
include(InstallRequiredSystemLibraries)
set(CPACK_GENERATOR "DEB")
set(CPACK_PACKAGE_NAME "libscrypt")
set(CPACK_PACKAGE_VERSION "1.0.0")
include(CPack)

# Thông báo cấu hình
message(STATUS "Da cau hinh xong du an. Muc tieu chinh: 'run_demo', 'test_scrypt', 'boundary_test', 'interoperability_test', 'memory_leak_test', 'thread_safety_test', 'benchmark_test'. Yeu cau libsodium cho 'interoperability_test'.")