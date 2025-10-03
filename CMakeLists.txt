# Đặt tên dự án là "PKI" và ngôn ngữ là C
project(PKI C)

# Tìm gói OpenSSL, yêu cầu phải có
find_package(OpenSSL REQUIRED COMPONENTS Crypto)

# Tìm pkg-config
find_package(PkgConfig REQUIRED)

# Tìm Check qua pkg-config
pkg_check_modules(CHECK REQUIRED check)

# Thêm các thư mục include
include_directories(${OPENSSL_INCLUDE_DIR} ${CHECK_INCLUDE_DIRS} ${CMAKE_CURRENT_SOURCE_DIR}/include)

# --- Định nghĩa Thư viện của chúng ta ---
# Tạo một thư viện tĩnh tên là "scrypt_crypto"
add_library(scrypt_crypto STATIC
    src/scrypt.c
    src/backend_openssl.c
)

# Chỉ định rằng thư mục "include" chứa các file header công khai của thư viện này
target_include_directories(scrypt_crypto PUBLIC 
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Liên kết thư viện của chúng ta với thư viện Crypto của OpenSSL
target_link_libraries(scrypt_crypto PRIVATE OpenSSL::Crypto)

# --- Định nghĩa Chương trình Demo ---
# Tạo file thực thi "run_demo" từ examples/main.c
add_executable(run_demo examples/main.c)
target_link_libraries(run_demo PRIVATE scrypt_crypto)

# --- Định nghĩa Chương trình Unit Test ---
# Tạo file thực thi "test_scrypt" từ src/test_scrypt.c
add_executable(test_scrypt src/test_scrypt.c)
target_link_libraries(test_scrypt PRIVATE scrypt_crypto ${CHECK_LIBRARIES})

# In ra thông báo trạng thái
message(STATUS "Da cau hinh xong du an. Muc tieu chinh: 'run_demo' va 'test_scrypt'.")