import 'dart:ffi';
import 'dart:io' show Platform;
import 'package:ffi/ffi.dart';
import 'package:flutter/foundation.dart'; // Để sử dụng compute


// --- Phần 1: Định nghĩa chữ ký các hàm C (FFI Typedefs) ---
// Đây là bản đồ 1-1 với các khai báo trong bmc_crypto.h

// Helper
typedef _GetPaddedSizeCFunc = Size Function(Size);
typedef _GetPaddedSizeDartFunc = int Function(int);

// CBC
typedef _EncryptCbcFunc = Int32 Function(Pointer<Uint8>, IntPtr, Pointer<Uint8>, Pointer<Uint8>, Pointer<Uint8>);
typedef _EncryptCbcDartFunc = int Function(Pointer<Uint8>, int, Pointer<Uint8>, Pointer<Uint8>, Pointer<Uint8>);
typedef _DecryptCbcFunc = Int32 Function(Pointer<Uint8>, IntPtr, Pointer<Uint8>, Pointer<Uint8>, Pointer<Uint8>, Pointer<IntPtr>);
typedef _DecryptCbcDartFunc = int Function(Pointer<Uint8>, int, Pointer<Uint8>, Pointer<Uint8>, Pointer<Uint8>, Pointer<IntPtr>);

// ECB
typedef _EncryptEcbFunc = Int32 Function(Pointer<Uint8>, IntPtr, Pointer<Uint8>, Pointer<Uint8>);
typedef _EncryptEcbDartFunc = int Function(Pointer<Uint8>, int, Pointer<Uint8>, Pointer<Uint8>);
typedef _DecryptEcbFunc = Int32 Function(Pointer<Uint8>, IntPtr, Pointer<Uint8>, Pointer<Uint8>, Pointer<IntPtr>);
typedef _DecryptEcbDartFunc = int Function(Pointer<Uint8>, int, Pointer<Uint8>, Pointer<Uint8>, Pointer<IntPtr>);

// CTR
typedef _XcryptCtrFunc = Int32 Function(Pointer<Uint8>, IntPtr, Pointer<Uint8>, Pointer<Uint8>, Pointer<Uint8>);
typedef _XcryptCtrDartFunc = int Function(Pointer<Uint8>, int, Pointer<Uint8>, Pointer<Uint8>, Pointer<Uint8>);

// SHA-256
typedef _Sha256Func = Void Function(Pointer<Uint8>, IntPtr, Pointer<Uint8>);
typedef _Sha256DartFunc = void Function(Pointer<Uint8>, int, Pointer<Uint8>);

// SHA-3
typedef _Sha3Func = Void Function(Pointer<Uint8>, IntPtr, Pointer<Uint8>);
typedef _Sha3DartFunc = void Function(Pointer<Uint8>, int, Pointer<Uint8>);


/// Lớp API chính để tương tác với thư viện mật mã native.
class BmcCrypto {
  /// Singleton pattern để đảm bảo chỉ có một instance của FFI bridge.
  static final BmcCrypto _instance = BmcCrypto._internal();
  factory BmcCrypto() => _instance;

  late final DynamicLibrary _dylib;

  // Khai báo các hàm FFI private
  late final _GetPaddedSizeDartFunc _getPaddedSize;
  late final _EncryptCbcDartFunc _encryptCbc128, _encryptCbc192, _encryptCbc256;
  late final _DecryptCbcDartFunc _decryptCbc128, _decryptCbc192, _decryptCbc256;
  late final _EncryptEcbDartFunc _encryptEcb128, _encryptEcb192, _encryptEcb256;
  late final _DecryptEcbDartFunc _decryptEcb128, _decryptEcb192, _decryptEcb256;
  late final _XcryptCtrDartFunc _xcryptCtr128, _xcryptCtr192, _xcryptCtr256;
  late final _Sha256DartFunc _sha256;
  late final _Sha3DartFunc _sha3_256, _sha3_384, _sha3_512;

  BmcCrypto._internal() {
    _dylib = _loadDylib();
    // Ánh xạ tất cả các hàm từ thư viện C vào các biến Dart
    _getPaddedSize = _dylib.lookup<NativeFunction<_GetPaddedSizeCFunc>>('bmc_aes_get_padded_size').asFunction<_GetPaddedSizeDartFunc>();

    // CBC
    _encryptCbc128 = _dylib.lookup<NativeFunction<_EncryptCbcFunc>>('bmc_aes128_cbc_encrypt').asFunction<_EncryptCbcDartFunc>();
    _decryptCbc128 = _dylib.lookup<NativeFunction<_DecryptCbcFunc>>('bmc_aes128_cbc_decrypt').asFunction<_DecryptCbcDartFunc>();
    _encryptCbc192 = _dylib.lookup<NativeFunction<_EncryptCbcFunc>>('bmc_aes192_cbc_encrypt').asFunction<_EncryptCbcDartFunc>();
    _decryptCbc192 = _dylib.lookup<NativeFunction<_DecryptCbcFunc>>('bmc_aes192_cbc_decrypt').asFunction<_DecryptCbcDartFunc>();
    _encryptCbc256 = _dylib.lookup<NativeFunction<_EncryptCbcFunc>>('bmc_aes256_cbc_encrypt').asFunction<_EncryptCbcDartFunc>();
    _decryptCbc256 = _dylib.lookup<NativeFunction<_DecryptCbcFunc>>('bmc_aes256_cbc_decrypt').asFunction<_DecryptCbcDartFunc>();

    // ECB
    _encryptEcb128 = _dylib.lookup<NativeFunction<_EncryptEcbFunc>>('bmc_aes128_ecb_encrypt').asFunction<_EncryptEcbDartFunc>();
    _decryptEcb128 = _dylib.lookup<NativeFunction<_DecryptEcbFunc>>('bmc_aes128_ecb_decrypt').asFunction<_DecryptEcbDartFunc>();
    _encryptEcb192 = _dylib.lookup<NativeFunction<_EncryptEcbFunc>>('bmc_aes192_ecb_encrypt').asFunction<_EncryptEcbDartFunc>();
    _decryptEcb192 = _dylib.lookup<NativeFunction<_DecryptEcbFunc>>('bmc_aes192_ecb_decrypt').asFunction<_DecryptEcbDartFunc>();
    _encryptEcb256 = _dylib.lookup<NativeFunction<_EncryptEcbFunc>>('bmc_aes256_ecb_encrypt').asFunction<_EncryptEcbDartFunc>();
    _decryptEcb256 = _dylib.lookup<NativeFunction<_DecryptEcbFunc>>('bmc_aes256_ecb_decrypt').asFunction<_DecryptEcbDartFunc>();

    // CTR
    _xcryptCtr128 = _dylib.lookup<NativeFunction<_XcryptCtrFunc>>('bmc_aes128_ctr_xcrypt').asFunction<_XcryptCtrDartFunc>();
    _xcryptCtr192 = _dylib.lookup<NativeFunction<_XcryptCtrFunc>>('bmc_aes192_ctr_xcrypt').asFunction<_XcryptCtrDartFunc>();
    _xcryptCtr256 = _dylib.lookup<NativeFunction<_XcryptCtrFunc>>('bmc_aes256_ctr_xcrypt').asFunction<_XcryptCtrDartFunc>();

    // SHA
    _sha256 = _dylib.lookup<NativeFunction<_Sha256Func>>('bmc_sha256').asFunction<_Sha256DartFunc>();
    _sha3_256 = _dylib.lookup<NativeFunction<_Sha3Func>>('bmc_sha3_256').asFunction<_Sha3DartFunc>();
    _sha3_384 = _dylib.lookup<NativeFunction<_Sha3Func>>('bmc_sha3_384').asFunction<_Sha3DartFunc>();
    _sha3_512 = _dylib.lookup<NativeFunction<_Sha3Func>>('bmc_sha3_512').asFunction<_Sha3DartFunc>();
  }

  DynamicLibrary _loadDylib() {
    if (Platform.isAndroid) return DynamicLibrary.open('libcryptographic_jni.so');
    if (Platform.isWindows) return DynamicLibrary.open('bmc_cryptographic.dll');
    if (Platform.isLinux) return DynamicLibrary.open('libbmc_cryptographic.so');
    if (Platform.isIOS || Platform.isMacOS) return DynamicLibrary.process();
    throw UnsupportedError('Unsupported platform');
  }

  // --- PUBLIC API METHODS ---

  /// Mã hóa AES-128-CBC. Trả về `null` nếu thất bại.
  Future<Uint8List?> aes128CbcEncrypt({required Uint8List plaintext, required Uint8List key, required Uint8List iv}) async {
    return compute(_aesCbcEncryptWorkload, {
      'function': _encryptCbc128,
      'getPaddedSize': _getPaddedSize,
      'plaintext': plaintext, 'key': key, 'iv': iv
    });
  }

  /// Giải mã AES-128-CBC. Trả về `null` nếu thất bại.
  Future<Uint8List?> aes128CbcDecrypt({required Uint8List ciphertext, required Uint8List key, required Uint8List iv}) async {
    return compute(_aesCbcDecryptWorkload, {
      'function': _decryptCbc128,
      'ciphertext': ciphertext, 'key': key, 'iv': iv
    });
  }
  /// Mã hóa AES-192-CBC. Trả về `null` nếu thất bại.
  Future<Uint8List?> aes192CbcEncrypt({required Uint8List plaintext, required Uint8List key, required Uint8List iv}) async {
    return compute(_aesCbcEncryptWorkload, {
      'function': _encryptCbc192,
      'getPaddedSize': _getPaddedSize,
      'plaintext': plaintext, 'key': key, 'iv': iv
    });
  }

  /// Giải mã AES-192-CBC. Trả về `null` nếu thất bại.
  Future<Uint8List?> aes192CbcDecrypt({required Uint8List ciphertext, required Uint8List key, required Uint8List iv}) async {
    return compute(_aesCbcDecryptWorkload, {
      'function': _decryptCbc192,
      'ciphertext': ciphertext, 'key': key, 'iv': iv
    });
  }
  /// Mã hóa AES-256-CBC. Trả về `null` nếu thất bại.
  Future<Uint8List?> aes256CbcEncrypt({required Uint8List plaintext, required Uint8List key, required Uint8List iv}) async {
    return compute(_aesCbcEncryptWorkload, {
      'function': _encryptCbc256,
      'getPaddedSize': _getPaddedSize,
      'plaintext': plaintext, 'key': key, 'iv': iv
    });
  }

  /// Giải mã AES-256-CBC. Trả về `null` nếu thất bại.
  Future<Uint8List?> aes256CbcDecrypt({required Uint8List ciphertext, required Uint8List key, required Uint8List iv}) async {
    return compute(_aesCbcDecryptWorkload, {
      'function': _decryptCbc256,
      'ciphertext': ciphertext, 'key': key, 'iv': iv
    });
  }

  /// Mã hóa AES-128-ECB. Trả về `null` nếu thất bại.
  Future<Uint8List?> aes128EcbEncrypt({required Uint8List plaintext, required Uint8List key}) async {
    return compute(_aesCbcEncryptWorkload, {
      'function': _encryptEcb128,
      'getPaddedSize': _getPaddedSize,
      'plaintext': plaintext, 'key': key, 'iv': null
    });
  }

  /// Giải mã AES-128-ECB. Trả về `null` nếu thất bại.
  Future<Uint8List?> aes128EcbDecrypt({required Uint8List ciphertext, required Uint8List key}) async {
    return compute(_aesCbcDecryptWorkload, {
      'function': _decryptEcb128,
      'ciphertext': ciphertext, 'key': key, 'iv': null
    });
  }

  /// Mã hóa AES-192-ECB. Trả về `null` nếu thất bại.
  Future<Uint8List?> aes192EcbEncrypt({required Uint8List plaintext, required Uint8List key}) async {
    return compute(_aesCbcEncryptWorkload, {
      'function': _encryptEcb192,
      'getPaddedSize': _getPaddedSize,
      'plaintext': plaintext, 'key': key, 'iv': null
    });
  }

  /// Giải mã AES-192-ECB. Trả về `null` nếu thất bại.
  Future<Uint8List?> aes192EcbDecrypt({required Uint8List ciphertext, required Uint8List key}) async {
    return compute(_aesCbcDecryptWorkload, {
      'function': _decryptEcb192,
      'ciphertext': ciphertext, 'key': key, 'iv': null
    });
  }
  /// Mã hóa AES-256-ECB. Trả về `null` nếu thất bại.
  Future<Uint8List?> aes256EcbEncrypt({required Uint8List plaintext, required Uint8List key}) async {
    return compute(_aesCbcEncryptWorkload, {
      'function': _encryptEcb256,
      'getPaddedSize': _getPaddedSize,
      'plaintext': plaintext, 'key': key, 'iv': null
    });
  }

  /// Giải mã AES-128-ECB. Trả về `null` nếu thất bại.
  Future<Uint8List?> aes256EcbDecrypt({required Uint8List ciphertext, required Uint8List key}) async {
    return compute(_aesCbcDecryptWorkload, {
      'function': _decryptEcb256,
      'ciphertext': ciphertext, 'key': key, 'iv': null
    });
  }

  /// Mã hóa AES-128-CTR. Trả về `null` nếu thất bại.
  Future<Uint8List?> aes128CtrEncrypt({required Uint8List plaintext, required Uint8List key, required Uint8List iv}) async {
    return compute(_aesCtrXcryptWorkload, {
      'function': _xcryptCtr128,
      'plaintext': plaintext, 'key': key, 'iv': iv
    });
  }

  /// Giải mã AES-128-CTR. Trả về `null` nếu thất bại.
  Future<Uint8List?> aes128CtrDecrypt({required Uint8List ciphertext, required Uint8List key, required Uint8List iv}) async {
    return compute(_aesCtrXcryptWorkload, {
      'function': _xcryptCtr128,
      'ciphertext': ciphertext, 'key': key, 'iv': iv
    });
  }
  /// Mã hóa AES-192-CTR. Trả về `null` nếu thất bại.
  Future<Uint8List?> aes192CtrEncrypt({required Uint8List plaintext, required Uint8List key, required Uint8List iv}) async {
    return compute(_aesCtrXcryptWorkload, {
      'function': _xcryptCtr192,
      'plaintext': plaintext, 'key': key, 'iv': iv
    });
  }

  /// Giải mã AES-192-CTR. Trả về `null` nếu thất bại.
  Future<Uint8List?> aes192CtrDecrypt({required Uint8List ciphertext, required Uint8List key, required Uint8List iv}) async {
    return compute(_aesCtrXcryptWorkload, {
      'function': _xcryptCtr192,
      'ciphertext': ciphertext, 'key': key, 'iv': iv
    });
  }
  /// Mã hóa AES-256-CTR. Trả về `null` nếu thất bại.
  Future<Uint8List?> aes256CtrEncrypt({required Uint8List plaintext, required Uint8List key, required Uint8List iv}) async {
    return compute(_aesCtrXcryptWorkload, {
      'function': _xcryptCtr256,
      'plaintext': plaintext, 'key': key, 'iv': iv
    });
  }

  /// Giải mã AES-256-CTR. Trả về `null` nếu thất bại.
  Future<Uint8List?> aes256CtrDecrypt({required Uint8List ciphertext, required Uint8List key, required Uint8List iv}) async {
    return compute(_aesCtrXcryptWorkload, {
      'function': _xcryptCtr256,
      'plaintext': ciphertext, 'key': key, 'iv': iv
    });
  }


  /// Băm dữ liệu bằng SHA-256.
  Future<Uint8List?> sha256(Uint8List data) async {
    return compute(_shaWorkload, {'function': _sha256, 'data': data, 'hashSize': 32});
  }

  /// Băm dữ liệu bằng SHA3-256.
  Future<Uint8List?> sha3_256(Uint8List data) async {
    return compute(_shaWorkload, {'function': _sha3_256, 'data': data, 'hashSize': 32});
  }
  /// Băm dữ liệu bằng SHA3-384.
  Future<Uint8List?> sha3_384(Uint8List data) async {
    return compute(_shaWorkload, {'function': _sha3_384, 'data': data, 'hashSize': 48});
  }
  /// Băm dữ liệu bằng SHA3-512.
  Future<Uint8List?> sha3_512(Uint8List data) async {
    return compute(_shaWorkload, {'function': _sha3_512, 'data': data, 'hashSize': 64});
  }
}


// --- Phần 2: Các hàm "Worker" để chạy trên Isolate riêng biệt ---
// Các hàm này phải là hàm top-level hoặc static.

// Worker cho mã hóa CBC/ECB
Future<Uint8List?> _aesCbcEncryptWorkload(Map<String, dynamic> args) async {
  final function = args['function'] as _EncryptCbcDartFunc;
  final getPaddedSize = args['getPaddedSize'] as _GetPaddedSizeDartFunc;
  final plaintext = args['plaintext'] as Uint8List;
  final key = args['key'] as Uint8List;
  final iv = args['iv'] as Uint8List;

  final pPtr = plaintext.allocatePointer();
  final kPtr = key.allocatePointer();
  final iPtr = iv.allocatePointer();

  final paddedSize = getPaddedSize(plaintext.length);
  final cPtr = calloc<Uint8>(paddedSize);

  try {
    final result = function(pPtr, plaintext.length, kPtr, iPtr, cPtr);
    if (result != 0) return null;
    return Uint8List.fromList(cPtr.asTypedList(paddedSize));
  } finally {
    calloc.free(pPtr);
    calloc.free(kPtr);
    calloc.free(iPtr);
    calloc.free(cPtr);
  }
}

// Worker cho giải mã CBC/ECB
Future<Uint8List?> _aesCbcDecryptWorkload(Map<String, dynamic> args) async {
  final function = args['function'] as _DecryptCbcDartFunc;
  final ciphertext = args['ciphertext'] as Uint8List;
  final key = args['key'] as Uint8List;
  final iv = args['iv'] as Uint8List;

  final cPtr = ciphertext.allocatePointer();
  final kPtr = key.allocatePointer();
  final iPtr = iv.allocatePointer();

  final pPtr = calloc<Uint8>(ciphertext.length);
  final outLenPtr = calloc<IntPtr>();

  try {
    final result = function(cPtr, ciphertext.length, kPtr, iPtr, pPtr, outLenPtr);
    if (result != 0) return null;
    final actualLen = outLenPtr.value;
    return Uint8List.fromList(pPtr.asTypedList(actualLen));
  } finally {
    calloc.free(cPtr);
    calloc.free(kPtr);
    calloc.free(iPtr);
    calloc.free(pPtr);
    calloc.free(outLenPtr);
  }
}
// Worker cho mã hóa / giải mã CTR
Future<Uint8List?> _aesCtrXcryptWorkload(Map<String, dynamic> args) async {
  final function = args['function'] as _XcryptCtrDartFunc;
  final plaintext = args['plaintext'] as Uint8List;
  final key = args['key'] as Uint8List;
  final iv = args['iv'] as Uint8List;

  final pPtr = plaintext.allocatePointer();
  final kPtr = key.allocatePointer();
  final iPtr = iv.allocatePointer();

  final cPtr = calloc<Uint8>(plaintext.length);

  try {
    final result = function(pPtr, plaintext.length, kPtr, iPtr, cPtr);
    if (result != 0) return null;
    return Uint8List.fromList(cPtr.asTypedList(plaintext.length));
  } finally {
    calloc.free(pPtr);
    calloc.free(kPtr);
    calloc.free(iPtr);
    calloc.free(cPtr);
  }
}

// Worker chung cho các hàm băm
Future<Uint8List?> _shaWorkload(Map<String, dynamic> args) async {
  final function = args['function'] as _Sha256DartFunc; // Sha3 cũng có cùng chữ ký
  final data = args['data'] as Uint8List;
  final hashSize = args['hashSize'] as int;

  final dataPtr = data.allocatePointer();
  final hashPtr = calloc<Uint8>(hashSize);

  try {
    function(dataPtr, data.length, hashPtr);
    return Uint8List.fromList(hashPtr.asTypedList(hashSize));
  } finally {
    calloc.free(dataPtr);
    calloc.free(hashPtr);
  }
}


// Extension helper để quản lý bộ nhớ dễ dàng hơn
extension Uint8ListBlobConversion on Uint8List {
  Pointer<Uint8> allocatePointer() {
    final ptr = calloc<Uint8>(length);
    ptr.asTypedList(length).setAll(0, this);
    return ptr;
  }
}