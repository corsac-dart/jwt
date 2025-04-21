/// Signer interface for JWT.
abstract class JWTSigner {
  /// The algorithm of this signer.
  String get algorithm;

  /// Optinal `kid` header to set in the signed token.
  String? get kid;

  List<int> sign(List<int> body);

  bool verify(List<int> body, List<int> signature);
}
