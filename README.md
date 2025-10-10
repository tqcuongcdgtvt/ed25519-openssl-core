
Thực hiện giai đoạn đầu - test từng test case

# ed25519-openssl-core

Kết quả Kiểm tra và Demo

Dưới đây là kết quả đầu ra từ việc chạy bộ kiểm thử và chương trình demo, xác nhận rằng tất cả các chức năng đều hoạt động chính xác.



Kết quả Chạy Bộ kiểm thử (Unit Tests)

Running suite(s): SHA256 Ed25519

Debug: Gọi backend->eddsa\_verify

Debug - Public Key: 968a7e2033558033cf62347b76294b997419e22b249a4306d2d4fb3fbf63b9ab

Debug - Signature: 2d8a160934de9535f7dda80acecf4dd387de7f5ff9d2c63246b1c7ad6a7a9cdbdca8f465749ebc7c45c05a317433e21040e0afa1918bcf33574a1e567292510d

Debug - Message (byte): 74 65 73 74 20 6d 65 73 73 61 67 65 

Debug: EVP\_DigestVerify returned 1

Debug: backend->eddsa\_verify trả về 0

Debug: Gọi backend->eddsa\_verify

Debug - Public Key: 52cb585adaa0236bff251f121086433214635b7a3205e5ffc1b6219ce673dbf8

Debug - Signature: f900fa36786fd68c38565cc7516ede336e6b0d8da0d585c7065a0dd876cf093180084567207d373296fd28d1ef65bf3b923f18792b2a6973b4cf6e0b3752cc07

Debug - Message (byte): 74 61 6d 70 65 72 65 64 20 6d 65 73 73 61 67 65 

Debug: EVP\_DigestVerify returned 0

Debug: backend->eddsa\_verify trả về 1

Debug: Gọi backend->eddsa\_verify

Debug - Public Key: 0000000000000000000000000000000000000000000000000000000000000000

Debug - Signature: 544aaf1694e30c928702f718cc3747c2e7c8acca1cbdab735ce520dc5016ea0b94b7eba4efd9353b3344ed972b2eaa2807a73a5e3f42acda02e4df6d1ace0e04

Debug - Message (byte): 74 65 73 74 20 6d 65 73 73 61 67 65 

Debug: EVP\_DigestVerify returned 0

Debug: backend->eddsa\_verify trả về 1

Debug: Gọi backend->eddsa\_verify

Debug - Public Key: 14172ca7459407accc1b6a25ed1a9d1b350ecb8aeb0e7d43c110372893c2a551

Debug - Signature: 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000

Debug - Message (byte): 74 65 73 74 20 6d 65 73 73 61 67 65 

Debug: EVP\_DigestVerify returned 0

Debug: backend->eddsa\_verify trả về 1

Debug: Gọi backend->eddsa\_verify

Debug - Public Key: 35e5e0ae9e6b7ac903b926dd55067f5e05c0746fe9ca18da539442d90f4aa45b

Debug - Signature: a5b9f375f7614405560466ac93d9bf712b924775224cc2188e1ed07ab3ac6c40f0fe0cdd467af2fdf63fdeda4915f102f942b08e4ea0140f7d6a6df460129e02

Debug - Message (byte): 

Debug: EVP\_DigestVerify returned 0

Debug: backend->eddsa\_verify trả về 1

100%: Checks: 9, Failures: 0, Errors: 0



Kết quả Chạy Chương trình Demo

--- Demo Thư viện Mã hóa Scrypt ---

--- 1. Test Chức năng Hash SHA-256 ---

Du lieu goc: day la du lieu can bam

SHA-256 Hash: ba683ab87fae6c41233565b2f7660877e993995d7573494f50e6d227efd735f1

\[OK] Hash thành công.

--- 2. Test Chu trình Ký và Xác thực Ed25519 ---

a. Đang tạo cặp khóa Ed25519...

&nbsp;  Public Key : 7f6fdd690b6e75514c4745e12cfa8d460dee5ba61d3443135ab16f811e0ad074

&nbsp;  \[OK] Tạo cặp khóa thành công.

b. Đang ký thông điệp...

&nbsp;  Thông điệp: "Thong diep nay can duoc ky va xac thuc"

&nbsp;  Signature  : f92c90d1acfaee905c2e61c3c957eb0147bbe86131705d4e516307bac004206f857e6bec9c608a23231eaaa76cd62896affa8480580dddcc1a9c5731ad86280b

&nbsp;  \[OK] Ký thành công.

c. Đang xác thực chữ ký hợp lệ...

Debug: Gọi backend->eddsa\_verify

Debug - Public Key: 7f6fdd690b6e75514c4745e12cfa8d460dee5ba61d3443135ab16f811e0ad074

Debug - Signature: f92c90d1acfaee905c2e61c3c957eb0147bbe86131705d4e516307bac004206f857e6bec9c608a23231eaaa76cd62896affa8480580dddcc1a9c5731ad86280b

Debug - Message (byte): 54 68 6f 6e 67 20 64 69 65 70 20 6e 61 79 20 63 61 6e 20 64 75 6f 63 20 6b 79 20 76 61 20 78 61 63 20 74 68 75 63 

Debug: EVP\_DigestVerify returned 1

Debug: backend->eddsa\_verify trả về 0

&nbsp;  >>> KẾT QUẢ: CHỮ KÝ HỢP LỆ.

&nbsp;  \[OK] Xác thực đúng.

d. Đang xác thực với thông điệp bị thay đổi...

&nbsp;  Thông điệp giả mạo: "Thong diep nay da bi thay doi!"

Debug: Gọi backend->eddsa\_verify

Debug - Public Key: 7f6fdd690b6e75514c4745e12cfa8d460dee5ba61d3443135ab16f811e0ad074

Debug - Signature: f92c90d1acfaee905c2e61c3c957eb0147bbe86131705d4e516307bac004206f857e6bec9c608a23231eaaa76cd62896affa8480580dddcc1a9c5731ad86280b

Debug - Message (byte): 54 68 6f 6e 67 20 64 69 65 70 20 6e 61 79 20 64 61 20 62 69 20 74 68 61 79 20 64 6f 69 21 

Debug: EVP\_DigestVerify returned 0

Debug: backend->eddsa\_verify trả về 1

&nbsp;  >>> KẾT QUẢ: CHỮ KÝ KHÔNG HỢP LỆ.

&nbsp;  \[OK] Phát hiện giả mạo thành công.

--- Test Hàm scrypt\_eddsa\_verify ---

Tạo cặp khóa thành công.

Public Key: cfef945d8cc3e947401059ee2a550f8c2ae654841f256088ad21ba4182e13c43

Ký thông điệp thành công.

Signature: acd748d18ba618885bfbd87410439c5ef9b5a14fdc35b991f394663645ee602cc47fb5faf0df7b0df7c621b109522b4e77625c3cc1687af8e4e93ee8a3066407

Test Case 1: Xác thực chữ ký hợp lệ...

&nbsp;  >>> KẾT QUẢ: CHỮ KÝ HỢP LỆ.

&nbsp;  \[OK] Test case 1 passed.

Test Case 2: Xác thực với thông điệp giả mạo...

&nbsp;  >>> KẾT QUẢ: CHỮ KÝ KHÔNG HỢP LỆ.

&nbsp;  \[OK] Test case 2 passed.

Test Case 3: Xác thực với khóa công khai sai...

&nbsp;  >>> KẾT QUẢ: CHỮ KÝ KHÔNG HỢP LỆ.

&nbsp;  \[OK] Test case 3 passed.

Test Case 4: Xác thực với chữ ký sai...

&nbsp;  >>> KẾT QUẢ: CHỮ KÝ KHÔNG HỢP LỆ.

&nbsp;  \[OK] Test case 4 passed.

Test Case 5: Xác thực với thông điệp rỗng...

&nbsp;  >>> KẾT QUẢ: CHỮ KÝ KHÔNG HỢP LỆ.

&nbsp;  \[OK] Test case 5 passed.

Test Case 6: Xác thực với khóa công khai rỗng...

&nbsp;  >>> KẾT QUẢ: CHỮ KÝ KHÔNG HỢP LỆ.

&nbsp;  \[OK] Test case 6 passed.

Test Case 7: Xác thực với chữ ký rỗng...

&nbsp;  >>> KẾT QUẢ: CHỮ KÝ KHÔNG HỢP LỆ.

&nbsp;  \[OK] Test case 7 passed.

--- Kết thúc kiểm tra scrypt\_eddsa\_verify ---

--- Demo hoàn tất. ---



