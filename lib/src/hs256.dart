import 'dart:convert';

import 'package:crypto/crypto.dart';

import 'signer.dart';

/// Signer implementing HMAC encryption using SHA256 hashing.
class JWTHmacSha256Signer implements JWTSigner {
  final List<int> secret;
  @override
  final String? kid;

  JWTHmacSha256Signer(String secret, {this.kid}) : secret = utf8.encode(secret);

  @override
  String get algorithm => 'HS256';

  @override
  List<int> sign(List<int> body) {
    final hmac = Hmac(sha256, secret);
    return hmac.convert(body).bytes;
  }

  @override
  bool verify(List<int> body, List<int> signature) {
    final actual = sign(body);
    if (actual.length == signature.length) {
      // constant-time comparison
      var isEqual = true;
      for (var i = 0; i < actual.length; i++) {
        if (actual[i] != signature[i]) isEqual = false;
      }
      return isEqual;
    } else {
      return false;
    }
  }
}
