import 'package:jose/jose.dart';

import 'signer.dart';

class JWTRsaSha256Signer implements JWTSigner {
  final JsonWebKey _jwk;

  @override
  final String? kid;

  JWTRsaSha256Signer._(this._jwk, this.kid);

  /// Creates new signer from specified PEM string
  factory JWTRsaSha256Signer({required String pem, String? kid}) {
    return JWTRsaSha256Signer._(JsonWebKey.fromPem(pem, keyId: kid), kid);
  }

  @override
  String get algorithm => 'RS256';

  @override
  List<int> sign(List<int> body) {
    return _jwk.sign(body, algorithm: algorithm);
  }

  @override
  bool verify(List<int> body, List<int> signature) {
    return _jwk.verify(body, signature, algorithm: algorithm);
  }
}
