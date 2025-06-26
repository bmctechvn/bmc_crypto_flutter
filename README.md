Chắc chắn rồi. Một file `README.md` tốt là bộ mặt của dự án trên GitHub, nó vừa mô tả sản phẩm, vừa là tài liệu hướng dẫn sử dụng đầu tiên cho bất kỳ ai quan tâm.

Dựa trên toàn bộ thư viện `bmc_cryptographic` mà chúng ta đã xây dựng, dưới đây là một file `README.md` hoàn chỉnh và chuyên nghiệp. Bạn có thể copy toàn bộ nội dung này, lưu vào một file tên là `README.md` và đưa lên thư mục gốc của project plugin `bmc_cryptographic_flutter`.

-----

# **BMC Cryptographic - Flutter Plugin**

[](https://www.google.com/search?q=https://pub.dev/packages/bmc_cryptographic_flutter)
[](https://opensource.org/licenses/MIT)

Một plugin Flutter đa nền tảng, hiệu năng cao, cung cấp các chức năng mật mã tiêu chuẩn bằng cách sử dụng `dart:ffi` để giao tiếp với một lõi thư viện C đã được kiểm chứng.

## Giới thiệu

`bmc_cryptographic_flutter` mang đến một giải pháp đơn giản và an toàn để thực hiện các tác vụ mã hóa và băm phổ biến trực tiếp trong ứng dụng Flutter của bạn. Bằng cách thực thi các thuật toán phức tạp trên mã C gốc, plugin đảm bảo hiệu năng vượt trội so với các triển khai bằng Dart thuần, đồng thời cung cấp một API Dart đơn giản và dễ sử dụng.

Toàn bộ các tác vụ nặng sẽ được thực thi trên một Isolate riêng biệt để không làm ảnh hưởng đến luồng giao diện người dùng (UI thread).

## Tính năng

  * **Mã hóa AES:**
      * **Kích thước khóa:** Hỗ trợ 128, 192, và 256-bit.
      * **Chế độ hoạt động:** Hỗ trợ CBC, ECB, và CTR.
      * **Đệm (Padding):** Tự động xử lý đệm PKCS\#7 cho chế độ CBC và ECB.
  * **Hàm băm (Hashing):**
      * **SHA-2:** Triển khai SHA-256.
      * **SHA-3:** Triển khai SHA3-256, SHA3-384, và SHA3-512.
  * **Hiệu năng cao:** Toàn bộ logic mật mã được xử lý bởi mã C gốc đã được tối ưu.
  * **Đa nền tảng:** Hỗ trợ đầy đủ cho Android, iOS, Windows, Linux, và macOS.

## Hỗ trợ Nền tảng

| Android | iOS | Linux | macOS | Windows |
| :---: |:---:|:---:|:---:|:---:|
|   ✅   |  ✅  |   ✅   |   ✅   |    ✅    |

## Cài đặt

Thêm dependency sau vào file `pubspec.yaml` của dự án Flutter của bạn:

```yaml
dependencies:
  flutter:
    sdk: flutter
  
  # Sử dụng path nếu bạn đang phát triển cục bộ
  bmc_cryptographic_flutter:
    path: ../path/to/your/plugin/bmc_cryptographic_flutter

  # Hoặc sử dụng git
  # bmc_cryptographic_flutter:
  #   git:
  #     url: https://github.com/bmctechvn/bmc_crypto_flutter.git
```

Sau đó, chạy lệnh sau trong terminal:

```bash
flutter pub get
```

## Hướng dẫn sử dụng

Import package và sử dụng đối tượng singleton `BmcCrypto` để truy cập tất cả các hàm.

```dart
import 'package:bmc_cryptographic_flutter/bmc_cryptographic_flutter.dart';
import 'dart:convert';
```

### Ví dụ 1: Mã hóa & Giải mã AES-128-CBC

Đây là một chu trình "khứ hồi" (round-trip) hoàn chỉnh.

```dart
Future<void> testAes128Cbc() async {
  // Khởi tạo đối tượng thư viện
  final crypto = BmcCrypto();

  // Chuẩn bị dữ liệu. Key và IV phải dài đúng 16 bytes cho AES-128.
  final plaintext = Uint8List.fromList(utf8.encode("Đây là một tin nhắn bí mật!"));
  final key = Uint8List.fromList(utf8.encode("my-super-secret-key-123456789"));
  final iv = Uint8List.fromList(utf8.encode("my-unique-iv-for-this-message"));

  print('--- AES-128-CBC Test ---');
  print('Plaintext: ${utf8.decode(plaintext)}');

  // Mã hóa
  final ciphertext = await crypto.aes128CbcEncrypt(
    plaintext: plaintext, 
    key: key, 
    iv: iv
  );

  if (ciphertext == null) {
    print('Encryption failed!');
    return;
  }
  print('Ciphertext (hex): ${ciphertext.map((b) => b.toRadixString(16).padLeft(2, '0')).join()}');

  // Giải mã
  final decrypted = await crypto.aes128CbcDecrypt(
    ciphertext: ciphertext, 
    key: key, 
    iv: iv
  );

  if (decrypted == null) {
    print('Decryption failed!');
    return;
  }
  print('Decrypted: ${utf8.decode(decrypted)}');

  // Xác minh
  assert(listEquals(plaintext, decrypted));
  print('✅ AES-128-CBC Test PASSED!');
}
```

### Ví dụ 2: Băm SHA-256

```dart
Future<void> testSha256() async {
  final crypto = BmcCrypto();
  final dataToHash = Uint8List.fromList(utf8.encode('abc'));
  
  // Vector test chuẩn của NIST
  final expectedHash = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

  print('\n--- SHA-256 Test ---');
  print("Input: 'abc'");
  
  final hash = await crypto.sha256(dataToHash);
  
  if (hash != null) {
    final hexHash = hash.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
    print('Actual hash:   $hexHash');
    print('Expected hash: $expectedHash');
    
    assert(hexHash == expectedHash);
    print('✅ SHA-256 Test PASSED!');
  }
}
```

### Ví dụ 3: Băm SHA3-512

```dart
Future<void> testSha3_512() async {
  final crypto = BmcCrypto();
  final dataToHash = Uint8List.fromList(utf8.encode("")); // Chuỗi rỗng

  // Vector test chuẩn của NIST cho chuỗi rỗng
  final expectedHash = "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26";

  print('\n--- SHA3-512 Test ---');
  print("Input: '' (empty string)");

  final hash = await crypto.sha3_512(dataToHash);

  if (hash != null) {
      final hexHash = hash.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
      print('Actual hash:   $hexHash');
      print('Expected hash: $expectedHash');
      
      assert(hexHash == expectedHash);
      print('✅ SHA3-512 Test PASSED!');
  }
}
```

## Tham chiếu API

Thư viện cung cấp một API tường minh và dễ đoán.

**Quy tắc đặt tên:** `bmc_aes<keysize>_<mode>_<operation>`

| Chức năng | Phương thức Dart | Ghi chú |
| :--- | :--- | :--- |
| Mã hóa AES-128 CBC | `aes128CbcEncrypt({plaintext, key, iv})` | Key và IV phải dài 16 bytes. |
| Giải mã AES-128 CBC | `aes128CbcDecrypt({ciphertext, key, iv})` | |
| Mã hóa AES-256 ECB | `aes256EcbEncrypt({plaintext, key})` | Key phải dài 32 bytes. **Không an toàn\!** |
| Mã hóa/Giải mã AES-192 CTR | `aes192CtrXcrypt({data, key, iv})` | Key 24 bytes, IV 16 bytes. |
| Băm SHA-256 | `sha256(data)` | Trả về hash dài 32 bytes. |
| Băm SHA3-512 | `sha3_512(data)` | Trả về hash dài 64 bytes. |
| ... | *và nhiều hàm khác* |

Vui lòng xem file `lib/bmc_cryptographic_flutter.dart` để có danh sách đầy đủ các hàm được hỗ trợ.

## Giấy phép

Dự án này được phát triển của BMC T&S JSC
