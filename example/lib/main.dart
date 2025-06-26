import 'dart:convert';
import 'package:flutter/foundation.dart';
import 'dart:async';
import 'package:bmc_cryptographic_flutter/bmc_cryptographic_flutter.dart';

Future<void> main() async {
  final crypto = BmcCrypto();

  // Test AES-256-CTR
  final key = Uint8List.fromList(utf8.encode('my-secret-key-16my-secret-key-16'));
  final iv = Uint8List.fromList(utf8.encode('my-unique-iv-16b'));
  final plaintext = Uint8List.fromList(utf8.encode('This is a test from Flutter!'));

  print('Encrypting AES...');
  final ciphertext = await crypto.aes256CtrEncrypt(plaintext: plaintext, key: key, iv: iv);

  if (ciphertext != null) {
    print('Decrypted AES...');
    final decrypted = await crypto.aes256CtrDecrypt(ciphertext: ciphertext, key: key, iv: iv);
    if (decrypted != null) {
      print('Result: ${utf8.decode(decrypted)}');
      assert(listEquals(plaintext, decrypted));
      print('✅ AES Test Passed!');
    }
  }

  // Test SHA-256
  print('\nHashing with SHA-256...');
  final dataToHash = Uint8List.fromList(utf8.encode('abc'));
  final hash = await crypto.sha256(dataToHash);
  if (hash != null) {
    final hexHash = hash.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
    print('SHA-256 hash of "abc": $hexHash');
    assert(hexHash == 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
    print('✅ SHA-256 Test Passed!');
  }

}