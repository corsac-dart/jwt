import 'package:jose/jose.dart';

import 'signer.dart';

/// The ES256 signer for JWTs.
class JWTEcdsaSha256Signer implements JWTSigner {
  final JsonWebKey _jwk;

  @override
  String get algorithm => 'ES256';

  @override
  final String? kid;

  JWTEcdsaSha256Signer.fromJWK(JsonWebKey jwk, this.kid) : _jwk = jwk;

  factory JWTEcdsaSha256Signer({required String pem, String? kid}) {
    return JWTEcdsaSha256Signer.fromJWK(JsonWebKey.fromPem(pem, keyId: kid), kid);
  }

  @override
  List<int> sign(List<int> body) {
    return _jwk.sign(body, algorithm: algorithm);
  }

  @override
  bool verify(List<int> body, List<int> signature) {
    return _jwk.verify(body, signature, algorithm: algorithm);
  }
}
