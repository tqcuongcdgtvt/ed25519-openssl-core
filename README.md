<h1 align="center">🔐 ED25519 OPENSSL CORE
</h1> 
<p align="center">
   Một nền tảng thực nghiệm PKI hiệu năng cao bằng C cho nghiên cứu mật mã ứng dụng.  
</p>

<p align="center">
  <img src="https://img.shields.io/badge/C-00599C?style=for-the-badge&logo=c" alt="C Version">
  <img src="https://img.shields.io/badge/CMake-FF6F00?style=for-the-badge&logo=cmake" alt="CMake Version">
  <img src="https://img.shields.io/badge/OpenSSL+-00A65A?style=for-the-badge&logo=openssl" alt="OpenSSL Version">
  
</p>

---

## Giới thiệu

**Ed25519 Openssl Core** cung cấp **một môi trường linh hoạt** cho việc thử nghiệm các thuật toán ký số và chứng thực. 
>  Mục tiêu chính là tạo ra một nền tảng mạnh mẽ để thực hiện các thử nghiệm đo lường chính xác, phục vụ cho việc kiểm chứng các lý thuyết trong lĩnh vực mật mã và an toàn hệ thống.
- Cho phép **kiểm soát và tinh chỉnh** các thành phần như quản lý khóa, ký số, và xác thực.
- Được xây dựng **bằng C kết hợp với Ed25519 - OpenSSL**, nhấn mạnh vào **hiệu năng cao và khả năng tích hợp**

---

##  Tính năng
- **Hiệu năng:** Ngôn ngữ: C hoặc C++ (ưu tiên C để dễ tích hợp với các thư viện crypto backend).
- **Bảo mật mạnh mẽ:** Tích hợp các thuật toán hiện đại như `Ed25519` qua OpenSSL. 
- **Linh hoạt & Mở rộng:** Dễ dàng tích hợp thuật toán mới hoặc các cơ chế lưu trữ khóa (HSM).
- **Tối ưu cho Linux:** Xây dựng và kiểm thử chủ yếu trên môi trường Ubuntu 18.04+.


---

##  Cấu trúc Thành phần

-  **0:** Chữ ký hợp lệ. 
-  **1:** Chữ ký không hợp lệ (invalid). 
-  **-1:** Lỗi (null pointer, message rỗng, hoặc lỗi OpenSSL).

---
## 📁 Cấu trúc thư mục
 <table>
            <thead>
                <tr>
                    <th>Thành phần</th>
                    <th>Mô tả</th>
                </tr>
            </thead>
            <tbody>
                <tr>
                    <td><code>dist/</code></td>
                    <td>Thư viện tĩnh/động chứa toàn bộ logic xử lý.</td>
                </tr>
                <tr>
                    <td><code>src/</code></td>
                    <td>Chứa mã nguồn backend cho OpenSSL và các hàm mã hóa scrypt..</td>
                </tr>
                 <tr>
                    <td><code>include/</code></td>
                    <td>Chứa các khóa riêng (private keys).</td>
                </tr>
                 <tr>
                    <td><code>tests/</code></td>
                    <td>Chứa các unit test để đảm bảo chất lượng code.</td>
                </tr>
            </tbody>
        </table>

---

##  Cài đặt & Sử dụng

<h3> Bước 1: Clone project</h3>
<pre><code>git clone https://github.com/tqcuongcdgtvt/ed25519-openssl-core.git
cd ed25519-openssl-core
</code></pre>

<h3> Bước 2: Cài thư viện Ubuntu/Debian</h3>
<p><strong>Yêu cầu:</strong> Ubuntu/Debian 18+</p>
<pre><code>sudo apt-get update 
</code></pre>

<h3> Bước 3: Cài đặt bộ công cụ biên dịch</h3>
<pre><code>sudo apt install build-essential  
</code></pre> 

<h3> Bước 4: Cài đặt thư viện phát triển của OpenSSL </h3>
<pre><code>sudo apt install libssl-dev  
</code></pre>

<h3> Bước 5: Kiểm tra </h3>
<pre><code>cd ~/Desktop/PKI
mkdir build
cd build
cmake ..
make 
./run_tests
</code></pre>
<h3> TestCase#1</h3>
<pre><code>Test Case 1: Xác thực chữ ký hợp lệ...
Debug: Gọi backend->eddsa_verify
Debug - Public Key: 87123eeaa9f97b9c0c5d3b261f8510d514da74f5f7533c1cb1178538f7ad7292
Debug - Signature: 697658a39d92cffd6a13379f608793a26312c8c671e7043c1a9db7ee3ddb4afd7d1207e3d3a1eafc8ce057df396ce12b25129e844a27eb695fe81606e66b850e
Debug - Message (byte): 54 68 6f 6e 67 20 64 69 65 70 20 6e 61 79 20 63 61 6e 20 64 75 6f 63 20 6b 79 20 76 61 20 78 61 63 20 74 68 75 63 
Debug: EVP_DigestVerify returned 1
Debug: backend->eddsa_verify trả về 0
   >>> KẾT QUẢ: CHỮ KÝ HỢP LỆ.
   [OK] Test case 1 passed.
</code></pre>
<h3> TestCase#2</h3>
<pre><code>Test Case 2: Xác thực với thông điệp giả mạo...
Debug: Gọi backend->eddsa_verify
Debug - Public Key: 87123eeaa9f97b9c0c5d3b261f8510d514da74f5f7533c1cb1178538f7ad7292
Debug - Signature: 697658a39d92cffd6a13379f608793a26312c8c671e7043c1a9db7ee3ddb4afd7d1207e3d3a1eafc8ce057df396ce12b25129e844a27eb695fe81606e66b850e
Debug - Message (byte): 54 68 6f 6e 67 20 64 69 65 70 20 6e 61 79 20 64 61 20 62 69 20 74 68 61 79 20 64 6f 69 21 
Debug: EVP_DigestVerify returned 0
Debug: backend->eddsa_verify trả về 1
   >>> KẾT QUẢ: CHỮ KÝ KHÔNG HỢP LỆ.
   [OK] Test case 2 passed.
</code></pre>
---
<h3> Kiểm tra các giá trị biên (Boundary-Value Testing)</h3>
<pre><code> ./boundary_test
</code></pre>
<h3> TestCase#1</h3>
<pre><code>Debug - Public Key: bf49f7008b1677e20ef899496418888d586b613b66c390fbe02856c6f135576f
Debug - Signature: 8b16570fa428fec3dea0c036931ef2f3703e56c29cf90e760898b496e2cde1eead17ded55596b36c263e5a1d6d25acea99a8b8ec2d068ed4f587a3ff70ac7f06
Debug - Message (byte): cc 00 00 00 00 00 00 00 00 00 
Debug: EVP_DigestVerify returned 1
Debug: backend->eddsa_verify trả về 0
</code></pre>
<h3> TestCase#2</h3>
<pre><code>Debug - Public Key: 3f61b0311f9d1c80d04ea07b9fb02faf36c1e39bd4f6fe4814c1c04d5066e525
Debug - Signature: 50593ab83d401206cd64f512fd99b2b4993bceb6eceb5f1bbf359a3d6895748f83d6037c76d3b91598fcf70019495d955a0d8249951dc01d3865ceb81d409707
Debug - Message (byte): cc 00 00 00 00 00 00 00 00 00 
Debug: EVP_DigestVerify returned 0
Debug: backend->eddsa_verify trả về -1
</code></pre>
<h3> Kiểm tra tính tương thích (Interoperability)</h3>
<pre><code>sudo apt update
sudo apt install libsodium-dev
./interoperability_test 
</code></pre>
<h3> TestCase#1</h3>
<pre><code>Public Key from libsodium (hex): b2aaed619eebcb536be9fe308d61f753fc82aa0cecbdc4bfa7f1079f086f7c2e
Signature from libsodium (hex): ec40fab2ee8a0ecf2798c5cb308797e2d4241935f801f12daf0ec453cadbb347dd4265b9c4d34a4eea7f60f3d4a21e98e69e81191b59875b8cd05fbcda89120e
Debug: Gọi backend->eddsa_verify
Debug - Public Key: b2aaed619eebcb536be9fe308d61f753fc82aa0cecbdc4bfa7f1079f086f7c2e
Debug - Signature: ec40fab2ee8a0ecf2798c5cb308797e2d4241935f801f12daf0ec453cadbb347dd4265b9c4d34a4eea7f60f3d4a21e98e69e81191b59875b8cd05fbcda89120e
Debug - Message (byte): 74 65 73 74 20 6d 65 73 73 61 67 65 
Debug: EVP_DigestVerify returned 1
Debug: backend->eddsa_verify trả về 0
</code></pre>
<h3> Kiểm tra lỗi cấp phát bộ nhớ (Memory Management)</h3>
<pre><code>sudo apt update
sudo apt install valgrind
valgrind --version
valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes ./test_scrypt
valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes ./boundary_test 
valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes ./interoperability_test
</code></pre>
<h3> TestCase#1 - 300s/1000 lần lặp</h3>
<pre><code>==6265== HEAP SUMMARY:
==6265==     in use at exit: 0 bytes in 0 blocks
==6265==   total heap usage: 193 allocs, 193 frees, 122,689 bytes allocated
==6265== All heap blocks were freed -- no leaks are possible
==6265== ERROR SUMMARY: 0 errors from 0 contexts (suppressed: 0 from 0)
</code></pre>
<h3> TestCase#1 - 700s/10000 lần lặp</h3>
<pre><code>Debug: backend->eddsa_verify trả về 0
Completed 10000 iterations successfully
==7696== HEAP SUMMARY:
==7696==     in use at exit: 1,068 bytes in 31 blocks
==7696==   total heap usage: 807,916 allocs, 807,885 frees, 303,066,498 bytes allocated
==7696== LEAK SUMMARY:
==7696==    definitely lost: 0 bytes in 0 blocks
==7696==    indirectly lost: 0 bytes in 0 blocks
==7696==      possibly lost: 0 bytes in 0 blocks
==7696==    still reachable: 1,068 bytes in 31 blocks
==7696==         suppressed: 0 bytes in 0 blocks
[Danh sách 31 loss records với tổng cộng 1,068 bytes still reachable]
==7696== ERROR SUMMARY: 0 errors from 0 contexts (suppressed: 0 from 0)
</code></pre>
<pre><code>Giải thích "still reachable"
Nguồn gốc: Bộ nhớ "still reachable" đến từ thư viện Check (các hàm như check_list_create, suite_create, tcase_create, srunner_create), được gọi trong main để thiết lập test suite. Đây là bộ nhớ được cấp phát để quản lý cấu trúc dữ liệu nội bộ của Check, nhưng không được tự động giải phóng vì chương trình kết thúc ngay sau khi test hoàn thành.
</code></pre>
<h3> Kiểm tra đa luồng (Concurrency/Thread Safety)</h3>
<pre><code>./thread_safety_test
valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes ./thread_safety_test
</code></pre>
<h3> TestCase#1 - 10 luồng (1 luồng = 1000 lần lập)</h3>
<pre><code>==8588== LEAK SUMMARY:
==8588==    definitely lost: 0 bytes in 0 blocks
==8588==    indirectly lost: 0 bytes in 0 blocks
==8588==      possibly lost: 0 bytes in 0 blocks
==8588==    still reachable: 1,068 bytes in 31 blocks
==8588==         suppressed: 0 bytes in 0 blocks
==8588== 
==8588== For lists of detected and suppressed errors, rerun with: -s
==8588== ERROR SUMMARY: 0 errors from 0 contexts (suppressed: 0 from 0)
100%: Checks: 1, Failures: 0, Errors: 0
Thread safety test passed! Ready for Valgrind.
==8587== 
==8587== HEAP SUMMARY:
==8587==     in use at exit: 0 bytes in 0 blocks
==8587==   total heap usage: 45 allocs, 45 frees, 15,479 bytes allocated
==8587== 
==8587== All heap blocks were freed -- no leaks are possible
==8587== 
==8587== For lists of detected and suppressed errors, rerun with: -s
==8587== ERROR SUMMARY: 0 errors from 0 contexts (suppressed: 0 from 0)
</code></pre>

<h3> Test bằng benmask </h3>
<pre><code>./benchmark_test
</code></pre>
<pre><code>Benchmark test completed. Total failures: 0
Total time: 7.9462 seconds
Average time per sign: 0.0002366241 seconds
Errors per second: 0.0000
100%: Checks: 1, Failures: 0, Errors: 0
Benchmark test passed!
</code></pre>
<h3>Chạy dưới Valgrind Massif (đo bộ nhớ từng luồng) Thời gian: 10 luồng x 1,000 lần lặp </h3>
<pre><code>valgrind --tool=massif --stacks=yes ./benchmark_test 
</code></pre>
<pre><code>544a7639ee34891a83f8a1c984fd2a7b02
Debug - Message (byte): 74 65 73 74 20 62 65 6e 63 68 6d 61 72 6b 
Debug: EVP_DigestVerify returned 1
Debug: backend->eddsa_verify trả về 0
Benchmark test completed. Total failures: 0
Total time: 73.2281 seconds
Average time per sign: 0.0024606337 seconds
Errors per second: 0.0000
==9042== 
100%: Checks: 1, Failures: 0, Errors: 0
Benchmark test passed!
==9041==
</code></pre>

## Đánh giá kết quả
<h3>Thời gian trung bình mỗi ký </h3>
<pre><code>0.0024606337 seconds (~2.46 ms).
</code></pre>
<pre><code>Đánh giá: Thời gian 0.00246 giây/ký (~2.46 ms) là hợp lý cho ED25519 trên phần cứng trung bình (tùy CPU, có thể tối ưu hơn với phần cứng mạnh hơn). Nếu cần tối ưu, có thể giảm overhead bằng cách giảm số luồng hoặc lặp ít hơn trong debug.
</code></pre>

## Mức tiêu thụ bộ nhớ
<pre><code>ms_print massif.out.0941  
ms_print massif.out.0942
</code></pre>

<h3>Mức tiêu thụ bộ nhớ từng luồng #1 </h3>

<pre><code>Stack: ~586-739 byte/luồng.
Heap: ~34,272 byte/luồng (tổng heap chia cho số luồng).
Tổng: ~34,858-35,011 byte/luồng.
Đánh giá: Mức tiêu thụ thấp và ổn định, không có rò rỉ.
</code></pre>
<h3>Mức tiêu thụ bộ nhớ từng luồng #2 </h3>
<pre><code>Stack/luồng: ~798-1,148 byte.
Heap/luồng: ~34,082-35,430 byte.
Tổng/luồng: ~34,880-36,578 byte.
Đánh giá: Mức tiêu thụ thấp và ổn định, không rò rỉ.
</code></pre>
