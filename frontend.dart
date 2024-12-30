import 'dart:convert';
import 'dart:typed_data';
import 'package:crypto/crypto.dart';
import 'package:encrypt/encrypt.dart' as encrypt;

class EncryptionService {
  static const String algorithm = 'AES-256-GCM';

  late encrypt.Key _key;
  late encrypt.IV _iv;
  String? _sessionToken;

  void initializeFromLogin(Map<String, dynamic> kms) {
    _key = encrypt.Key(base64.decode(kms['key']));
    _iv = encrypt.IV(base64.decode(kms['iv']));
    _sessionToken = kms['sessionToken'];
  }

  String encryptData(String data) {
    if (_sessionToken == null) {
      throw Exception('Session not initialized');
    }

    final encrypter =
        encrypt.Encrypter(encrypt.AES(_key, mode: encrypt.AESMode.gcm));

    final encrypted = encrypter.encrypt(data, iv: _iv);
    return '${encrypted.bytes}:${encrypted.mac}:${_iv.bytes}';
  }

  String decryptData(String encryptedData) {
    if (_sessionToken == null) {
      throw Exception('Session not initialized');
    }

    final parts = encryptedData.split(':');
    if (parts.length != 3) {
      throw Exception('Invalid encrypted data format');
    }

    final encryptedBytes = base64.decode(parts[0]);
    final authTag = base64.decode(parts[1]);
    final iv = encrypt.IV(base64.decode(parts[2]));

    final encrypter =
        encrypt.Encrypter(encrypt.AES(_key, mode: encrypt.AESMode.gcm));

    return encrypter.decrypt64(base64.encode(encryptedBytes),
        iv: iv, mac: encrypt.Mac(authTag));
  }

  String? get sessionToken => _sessionToken;
}
