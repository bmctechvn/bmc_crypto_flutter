import 'dart:ffi';
import 'dart:io' show Platform;
import 'package:ffi/ffi.dart';
import 'package:flutter/foundation.dart'; // Để sử dụng compute

final class SecureSession extends Opaque {}

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


// --- PHẦN BỔ SUNG: Typedefs cho Secure Session ---
typedef _SessionInitFunc = Int32 Function();
typedef _SessionInitDartFunc = int Function();

typedef _SessionGenerateKeyPairFunc = Void Function(Pointer<Uint8>, Pointer<Uint8>);
typedef _SessionGenerateKeyPairDartFunc = void Function(Pointer<Uint8>, Pointer<Uint8>);

typedef _SessionStartFunc = Int32 Function(Pointer<Pointer<SecureSession>>, Pointer<Uint8>, Pointer<Uint8>, Pointer<Uint8>, Int32);
typedef _SessionStartDartFunc = int Function(Pointer<Pointer<SecureSession>>, Pointer<Uint8>, Pointer<Uint8>, Pointer<Uint8>, int);

typedef _SessionEncryptFunc = Int32 Function(Pointer<SecureSession>, Pointer<Uint8>, IntPtr, Pointer<Uint8>, Pointer<IntPtr>);
typedef _SessionEncryptDartFunc = int Function(Pointer<SecureSession>, Pointer<Uint8>, int, Pointer<Uint8>, Pointer<IntPtr>);

typedef _SessionDecryptFunc = Int32 Function(Pointer<SecureSession>, Pointer<Uint8>, IntPtr, Pointer<Uint8>, Pointer<IntPtr>);
typedef _SessionDecryptDartFunc = int Function(Pointer<SecureSession>, Pointer<Uint8>, int, Pointer<Uint8>, Pointer<IntPtr>);

typedef _SessionDestroyFunc = Void Function(Pointer<SecureSession>);
typedef _SessionDestroyDartFunc = void Function(Pointer<SecureSession>);
// --- KẾT THÚC PHẦN BỔ SUNG ---

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
// --- BỔ SUNG: Khai báo hàm FFI cho Secure Session ---
  late final _SessionInitDartFunc _sessionInit;
  late final _SessionGenerateKeyPairDartFunc _sessionGenerateKeyPair;
  late final _SessionStartDartFunc _sessionStart;
  late final _SessionEncryptDartFunc _sessionEncrypt;
  late final _SessionDecryptDartFunc _sessionDecrypt;
  late final _SessionDestroyDartFunc _sessionDestroy;
  // --- KẾT THÚC PHẦN BỔ SUNG ---

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
    // --- BỔ SUNG: Ánh xạ hàm Secure Session ---
    _sessionInit = _dylib.lookup<NativeFunction<_SessionInitFunc>>('secure_session_init').asFunction<_SessionInitDartFunc>();
    _sessionGenerateKeyPair = _dylib.lookup<NativeFunction<_SessionGenerateKeyPairFunc>>('secure_generate_keypair').asFunction<_SessionGenerateKeyPairDartFunc>();
    _sessionStart = _dylib.lookup<NativeFunction<_SessionStartFunc>>('secure_session_start').asFunction<_SessionStartDartFunc>();
    _sessionEncrypt = _dylib.lookup<NativeFunction<_SessionEncryptFunc>>('secure_session_encrypt').asFunction<_SessionEncryptDartFunc>();
    _sessionDecrypt = _dylib.lookup<NativeFunction<_SessionDecryptFunc>>('secure_session_decrypt').asFunction<_SessionDecryptDartFunc>();
    _sessionDestroy = _dylib.lookup<NativeFunction<_SessionDestroyFunc>>('secure_session_destroy').asFunction<_SessionDestroyDartFunc>();
    // --- KẾT THÚC PHẦN BỔ SUNG ---
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
  // --- BỔ SUNG: Public API cho Secure Session ---

  /// Khởi tạo thư viện libsodium. Nên gọi một lần khi ứng dụng khởi động.
  /// Trả về 0 nếu thành công.
  int sessionInit() {
    return _sessionInit();
  }

  /// Tạo một cặp khóa định danh (public & secret key).
  Future<SessionKeyPair?> sessionGenerateKeyPair() async {
    return compute(_sessionGenerateKeyPairWorkload, {'function': _sessionGenerateKeyPair});
  }

  /// Bắt đầu một phiên bảo mật. Trả về một handle (con trỏ) tới phiên.
  /// Trả về 0 nếu thất bại.
  Future<int> sessionStart({required Uint8List myPk, required Uint8List mySk, required Uint8List theirPk, required bool isInitiator}) async {
    return compute(_sessionStartWorkload, {
      'function': _sessionStart,
      'myPk': myPk, 'mySk': mySk, 'theirPk': theirPk,
      'isInitiator': isInitiator ? 1 : 0
    });
  }

  /// Mã hóa dữ liệu trong một phiên. Trả về `null` nếu thất bại.
  Future<Uint8List?> sessionEncrypt({required int sessionHandle, required Uint8List plaintext}) async {
    if (sessionHandle == 0) return null;
    return compute(_sessionEncryptWorkload, {
      'function': _sessionEncrypt,
      'sessionHandle': sessionHandle,
      'plaintext': plaintext
    });
  }

  /// Giải mã dữ liệu trong một phiên. Trả về `null` nếu thất bại.
  Future<Uint8List?> sessionDecrypt({required int sessionHandle, required Uint8List ciphertext}) async {
    if (sessionHandle == 0) return null;
    return compute(_sessionDecryptWorkload, {
      'function': _sessionDecrypt,
      'sessionHandle': sessionHandle,
      'ciphertext': ciphertext
    });
  }

  /// Hủy phiên làm việc và giải phóng bộ nhớ.
  Future<void> sessionDestroy({required int sessionHandle}) async {
    if (sessionHandle != 0) {
      // Chạy trên isolate để giải phóng bộ nhớ không ảnh hưởng UI
      return compute(_sessionDestroyWorkload, {
        'function': _sessionDestroy,
        'sessionHandle': sessionHandle,
      });
    }
  }
// --- KẾT THÚC PHẦN BỔ SUNG ---
}
// --- Lớp helper để chứa cặp khóa ---
class SessionKeyPair {
  final Uint8List pk; // Public Key
  final Uint8List sk; // Secret Key
  SessionKeyPair(this.pk, this.sk);
}
// --- KẾT THÚC LỚP HELPER ---

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
// --- PHẦN BỔ SUNG: Worker functions cho Secure Session ---

const int _keyBytes = 32; // Kích thước khóa của Curve25519

Future<SessionKeyPair?> _sessionGenerateKeyPairWorkload(Map<String, dynamic> args) async {
  final function = args['function'] as _SessionGenerateKeyPairDartFunc;

  final pkPtr = calloc<Uint8>(_keyBytes);
  final skPtr = calloc<Uint8>(_keyBytes);

  try {
    function(pkPtr, skPtr);
    return SessionKeyPair(
      Uint8List.fromList(pkPtr.asTypedList(_keyBytes)),
      Uint8List.fromList(skPtr.asTypedList(_keyBytes)),
    );
  } finally {
    calloc.free(pkPtr);
    calloc.free(skPtr);
  }
}

Future<int> _sessionStartWorkload(Map<String, dynamic> args) async {
  final function = args['function'] as _SessionStartDartFunc;
  final myPk = args['myPk'] as Uint8List;
  final mySk = args['mySk'] as Uint8List;
  final theirPk = args['theirPk'] as Uint8List;
  final isInitiator = args['isInitiator'] as int;

  final myPkPtr = myPk.allocatePointer();
  final mySkPtr = mySk.allocatePointer();
  final theirPkPtr = theirPk.allocatePointer();
  // Cấp phát một con trỏ để nhận về con trỏ session
  final sessionPtrPtr = calloc<Pointer<SecureSession>>();

  try {
    final result = function(sessionPtrPtr, myPkPtr, mySkPtr, theirPkPtr, isInitiator);
    if (result != 0) {
      return 0; // Thất bại
    }
    // Trả về địa chỉ của session handle
    return sessionPtrPtr.value.address;
  } finally {
    calloc.free(myPkPtr);
    calloc.free(mySkPtr);
    calloc.free(theirPkPtr);
    calloc.free(sessionPtrPtr);
  }
}


Future<Uint8List?> _sessionEncryptWorkload(Map<String, dynamic> args) async {
  final function = args['function'] as _SessionEncryptDartFunc;
  final sessionHandle = args['sessionHandle'] as int;
  final plaintext = args['plaintext'] as Uint8List;

  // Chuyển handle (địa chỉ) thành con trỏ thực
  final sessionPtr = Pointer<SecureSession>.fromAddress(sessionHandle);

  final pPtr = plaintext.allocatePointer();
  final cPtr = calloc<Uint8>(plaintext.length + 12 + 16);
  final cLenPtr = calloc<IntPtr>();

  try {
    final result = function(sessionPtr, pPtr, plaintext.length, cPtr, cLenPtr);
    if (result != 0) return null;
    return Uint8List.fromList(cPtr.asTypedList(cLenPtr.value));
  } finally {
    calloc.free(pPtr);
    calloc.free(cPtr);
    calloc.free(cLenPtr);
  }
}
Future<Uint8List?> _sessionDecryptWorkload(Map<String, dynamic> args) async {
  final function = args['function'] as _SessionDecryptDartFunc;
  final sessionHandle = args['sessionHandle'] as int;
  final ciphertext = args['ciphertext'] as Uint8List;

  final sessionPtr = Pointer<SecureSession>.fromAddress(sessionHandle);

  final cPtr = ciphertext.allocatePointer();
  final dPtr = calloc<Uint8>(ciphertext.length);
  final dLenPtr = calloc<IntPtr>();

  try {
    final result = function(sessionPtr, cPtr, ciphertext.length, dPtr, dLenPtr);
    if (result != 0) return null;
    return Uint8List.fromList(dPtr.asTypedList(dLenPtr.value));
  } finally {
    calloc.free(cPtr);
    calloc.free(dPtr);
    calloc.free(dLenPtr);
  }
}
Future<void> _sessionDestroyWorkload(Map<String, dynamic> args) async {
  final function = args['function'] as _SessionDestroyDartFunc;
  final sessionHandle = args['sessionHandle'] as int;
  final sessionPtr = Pointer<SecureSession>.fromAddress(sessionHandle);
  function(sessionPtr);
}

// --- KẾT THÚC PHẦN BỔ SUNG ---


// Extension helper để quản lý bộ nhớ dễ dàng hơn
extension Uint8ListBlobConversion on Uint8List {
  Pointer<Uint8> allocatePointer() {
    final ptr = calloc<Uint8>(length);
    ptr.asTypedList(length).setAll(0, this);
    return ptr;
  }
}