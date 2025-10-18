# Scrypt Crypto Library

A cryptographic library supporting Ed25519 signatures and SHA-2 hashing using OpenSSL.

## Dependencies
- OpenSSL (installed on the system)
- CMake (for building examples)
- (Optional) libsodium for interoperability tests

## Included Files
- `libscrypt_crypto_static.a`: Static library
- `libscrypt_crypto.so`: Shared library
- `scrypt.h`: Header file
- `example.c`: Example usage

## Installation
1. Copy the library and header to your system:
   ```bash
   sudo cp libscrypt_crypto_static.a /usr/local/lib/
   sudo cp libscrypt_crypto.so /usr/local/lib/
   sudo cp scrypt.h /usr/local/include/

Update library cache (optional):
bashsudo ldconfig


Usage
Compile with Static Library
bashgcc example.c -o myapp -lscrypt_crypto_static -lssl -lcrypto -I/usr/local/include -L/usr/local/lib
./myapp
Compile with Shared Library
bashgcc example.c -o myapp -lscrypt_crypto -lssl -lcrypto -I/usr/local/include -L/usr/local/lib -Wl,-rpath=/usr/local/lib
./myapp
Or set runtime path:
bashexport LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH
./myapp
Example Code
See example.c for a demo of SHA-256 hashing and Ed25519 signing/verification.
License
[Specify your license here, e.g., MIT, GPL] - Add if applicable.
Contact
For support, contact [your email or link].
text- Điều chỉnh nội dung (license, contact) theo ý bạn.

##### d. **Tạo gói nén**
- Nén thư mục `dist` để gửi cho người khác:
  ```bash:disable-run
  cd /home/ubuntu/Desktop/PKI
  tar -czvf scrypt_crypto_v1.0.0.tar.gz dist/