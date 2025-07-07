import 'dart:convert';
import 'package:flutter/foundation.dart';
import 'dart:async';
import 'package:bmc_cryptographic_flutter/bmc_cryptographic_flutter.dart';

final crypto = BmcCrypto();

Future<void> main() async {

  // Test AES-256-CTR
  funAESTest();
  // Test SHA-256
  funSHATest();
  // Secure Session
  funSessionSecure();
}
Future<void> funAESTest() async {
  final key = Uint8List.fromList(
      utf8.encode('my-secret-key-16my-secret-key-16'));
  final iv = Uint8List.fromList(utf8.encode('my-unique-iv-16b'));
  var plaintext = Uint8List.fromList(
      utf8.encode('This is a test from Flutter!'));

  print('Encrypting AES...');
  var ciphertext = await crypto.aes256CtrEncrypt(
      plaintext: plaintext, key: key, iv: iv);

  if (ciphertext != null) {
    print('Decrypted AES...');
    final decrypted = await crypto.aes256CtrDecrypt(
        ciphertext: ciphertext, key: key, iv: iv);
    if (decrypted != null) {
      print('Result: ${utf8.decode(decrypted)}');
      assert(listEquals(plaintext, decrypted));
      print('✅ AES Test Passed!');
    }
  }
}
Future<void> funSHATest()async {

  print('\nHashing with SHA-256...');
  final dataToHash = Uint8List.fromList(utf8.encode('abc'));
  final hash = await crypto.sha256(dataToHash);
  if (hash != null) {
    final hexHash = hash
        .map((b) => b.toRadixString(16).padLeft(2, '0'))
        .join();
    print('SHA-256 hash of "abc": $hexHash');
    assert(hexHash ==
        'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
    print('✅ SHA-256 Test Passed!');
  }
}
Future<void> funSessionSecure() async {
  // 1. Khởi tạo
  crypto.sessionInit();
  debugPrint("Init OK");

  // 2. Tạo khóa
  final aliceKeyPair = await crypto.sessionGenerateKeyPair();
  final bobKeyPair = await crypto.sessionGenerateKeyPair();
  if (aliceKeyPair == null || bobKeyPair == null) {
    debugPrint("Lỗi tạo khóa");
    return;
  }
  debugPrint("Tạo khóa OK");

  // 3. Bắt đầu phiên
  final aliceSession = await crypto.sessionStart(
    myPk: aliceKeyPair.pk,
    mySk: aliceKeyPair.sk,
    theirPk: bobKeyPair.pk,
    isInitiator: true,
  );
  final bobSession = await crypto.sessionStart(
    myPk: bobKeyPair.pk,
    mySk: bobKeyPair.sk,
    theirPk: aliceKeyPair.pk,
    isInitiator: false,
  );
  if (aliceSession == 0 || bobSession == 0) {
    debugPrint("Lỗi bắt đầu phiên");
    return;
  }
  debugPrint("Bắt đầu phiên OK. Alice: $aliceSession, Bob: $bobSession");

  // 4. Mã hóa và giải mã
  final message = "Hello Flutter FFI!";
  final plaintext = Uint8List.fromList(utf8.encode(message));
  debugPrint("Tin nhắn gốc: $message");

  final ciphertext = await crypto.sessionEncrypt(sessionHandle: aliceSession, plaintext: plaintext);
  if (ciphertext == null) {
    debugPrint("Lỗi mã hóa");
    return;
  }
  debugPrint("Mã hóa OK");

  final decrypted = await crypto.sessionDecrypt(sessionHandle: bobSession, ciphertext: ciphertext);
  if (decrypted == null) {
    debugPrint("Lỗi giải mã");
    return;
  }
  final decryptedMessage = utf8.decode(decrypted);
  debugPrint("Tin nhắn đã giải mã: $decryptedMessage");

  // 5. So sánh
  if (message == decryptedMessage) {
    debugPrint("✅ TEST THÀNH CÔNG!");
  } else {
    debugPrint("❌ TEST THẤT BẠI!");
  }

  // 6. Hủy phiên
  crypto.sessionDestroy(sessionHandle: aliceSession);
  crypto.sessionDestroy(sessionHandle: bobSession);
  debugPrint("Hủy phiên OK");

}