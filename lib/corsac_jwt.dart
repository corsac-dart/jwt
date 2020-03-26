library corsac_jwt;

/// Lightweight JSON Web Token (JWT) implementation.
///
/// ## Usage
///
///     void main() {
///       var builder = new JWTBuilder();
///       var token = builder
///         ..issuer = 'https://api.foobar.com'
///         ..expiresAt = new DateTime.now().add(new Duration(minutes: 3))
///         ..setClaim('data', {'userId': 836})
///         ..getToken(); // returns token without signature
///
///       var signer = new JWTHmacSha256Signer();
///       var signedToken = builder.getSignedToken(signer, 'sharedSecret');
///       print(signedToken); // prints encoded JWT
///       var stringToken = signedToken.toString();
///
///       var decodedToken = new JWT.parse(stringToken);
///       // Verify signature:
///       print(decodedToken.verify(signer, 'sharedSecret')); // true
///
///       // Validate claims:
///       var validator = new JWTValidator() // uses DateTime.now() by default
///         ..issuer = 'https://api.foobar.com'; // set claims you wish to validate
///       Set<String> errors = validator.validate(decodedToken);
///       print(errors); // (empty list)
///     }
///

import 'dart:typed_data';
import 'dart:convert';

import 'package:crypto/crypto.dart';
import 'package:pointycastle/pointycastle.dart';
import 'package:rsa_pkcs/rsa_pkcs.dart' as rsa;
import 'package:logging/logging.dart';

Logger _logger = new Logger('JWTRsaSha256Signer');

class JWTRsaSha256Signer implements JWTSigner {
  final rsa.RSAPrivateKey _privateKey;
  final rsa.RSAPublicKey _publicKey;

  JWTRsaSha256Signer._(this._privateKey, this._publicKey);

  /// Creates new signer.
  ///
  /// [privateKey] is only required when signing new tokens and otherwise can
  /// be left as `null`. Similarly [publicKey] is only used to verify existing
  /// signatures.
  ///
  /// Both `privateKey` and `publicKey` are expected to be strings in PEM
  /// format.
  factory JWTRsaSha256Signer(
      {String privateKey, String publicKey, String password}) {
    rsa.RSAPKCSParser parser = new rsa.RSAPKCSParser();

    rsa.RSAPrivateKey priv;
    rsa.RSAPublicKey pub;
    if (privateKey is String) {
      rsa.RSAKeyPair pair = parser.parsePEM(privateKey, password: password);
      if (pair.private is! rsa.RSAPrivateKey)
        throw new JWTError('Invalid private RSA key.');
      priv = pair.private;
    }

    if (publicKey is String) {
      rsa.RSAKeyPair pair = parser.parsePEM(publicKey, password: password);
      if (pair.public is! rsa.RSAPublicKey)
        throw new JWTError('Invalid public RSA key.');
      pub = pair.public;
    }
    return new JWTRsaSha256Signer._(priv, pub);
  }

  @override
  String get algorithm => 'RS256';

  @override
  List<int> sign(List<int> body) {
    if (_privateKey == null) {
      throw new StateError(
          'RS256 signer requires private key to create signatures.');
    }
    var s = new Signer('SHA-256/RSA');
    var key = new RSAPrivateKey(_privateKey.modulus,
        _privateKey.privateExponent, _privateKey.prime1, _privateKey.prime2);
    var param = new ParametersWithRandom(
        new PrivateKeyParameter<RSAPrivateKey>(key),
        new SecureRandom("AES/CTR/PRNG"));

    s.init(true, param);
    RSASignature signature = s.generateSignature(new Uint8List.fromList(body));

    return signature.bytes.toList(growable: false);
  }

  @override
  bool verify(List<int> body, List<int> signature) {
    if (_publicKey == null) {
      throw new StateError(
          'RS256 signer requires public key to verify signatures.');
    }

    try {
      var s = new Signer('SHA-256/RSA');
      var key = new RSAPublicKey(
          _publicKey.modulus, new BigInt.from(_publicKey.publicExponent));
      var param = new ParametersWithRandom(
          new PublicKeyParameter<RSAPublicKey>(key),
          new SecureRandom("AES/CTR/PRNG"));

      s.init(false, param);
      var rsaSignature = new RSASignature(new Uint8List.fromList(signature));
      return s.verifySignature(new Uint8List.fromList(body), rsaSignature);
    } catch (e) {
      _logger.warning(
          'RS256 token verification failed with following error: ${e}.', e);
      return false;
    }
  }
}

final _jsonToBase64Url = json.fuse(utf8.fuse(base64Url));

int _secondsSinceEpoch(DateTime dateTime) {
  return (dateTime.millisecondsSinceEpoch / 1000).floor();
}

String _base64Padded(String value) {
  var mod = value.length % 4;
  if (mod == 0) {
    return value;
  } else if (mod == 3) {
    return value.padRight(value.length + 1, '=');
  } else if (mod == 2) {
    return value.padRight(value.length + 2, '=');
  } else {
    return value; // let it fail when decoding
  }
}

String _base64Unpadded(String value) {
  if (value.endsWith('==')) return value.substring(0, value.length - 2);
  if (value.endsWith('=')) return value.substring(0, value.length - 1);
  return value;
}

/// Error thrown by `JWT` when parsing tokens from string.
class JWTError implements Exception {
  final String message;

  JWTError(this.message);

  @override
  String toString() => 'JWTError: $message';
}

/// JSON Web Token.
class JWT {
  /// List of standard (reserved) claims.
  static const Iterable<String> reservedClaims = const [
    'iss',
    'aud',
    'iat',
    'exp',
    'nbf',
    'sub',
    'jti'
  ];

  Map<String, String> _headers;
  Map<String, dynamic> _claims;

  // Allows access to the full claims Map
  Map<String, dynamic> get claims => Map.from(_claims);

  /// Contains original Base64 encoded token header.
  final String encodedHeader;

  /// Contains original Base64 encoded token payload (claims).
  final String encodedPayload;

  /// Contains original Base64 encoded token signature, or `null`
  /// if token is unsigned.
  final String signature;

  JWT._(this.encodedHeader, this.encodedPayload, this.signature) {
    try {
      /// Dart's built-in BASE64URL codec needs padding (SDK 1.17).
      _headers = new Map<String, String>.from(
          _jsonToBase64Url.decode(_base64Padded(encodedHeader)));
      _claims = new Map<String, dynamic>.from(
          _jsonToBase64Url.decode(_base64Padded(encodedPayload)));
    } catch (e) {
      throw new JWTError('Could not decode token string. Error: ${e}.');
    }
  }

  /// Parses [token] string and creates new instance of [JWT].
  /// Throws [JWTError] if parsing fails.
  factory JWT.parse(String token) {
    var parts = token.split('.');
    if (parts.length == 2) {
      return new JWT._(parts.first, parts.last, null);
    } else if (parts.length == 3) {
      return new JWT._(parts[0], parts[1], parts[2]);
    } else {
      throw new JWTError('Invalid token string format for JWT.');
    }
  }

  /// Algorithm used to sign this token. The value `none` means this token
  /// is not signed.
  ///
  /// One should not rely on this value to determine the algorithm used to sign
  /// this token.
  String get algorithm => _headers['alg'];

  /// The issuer of this token (value of standard `iss` claim).
  String get issuer => _claims['iss'];

  /// The audience of this token (value of standard `aud` claim).
  String get audience => _claims['aud'];

  /// The time this token was issued (value of standard `iat` claim).
  int get issuedAt => _claims['iat'];

  /// The expiration time of this token (value of standard `exp` claim).
  int get expiresAt => _claims['exp'];

  /// The time before which this token must not be accepted (value of standard
  /// `nbf` claim).
  int get notBefore => _claims['nbf'];

  /// Identifies the principal that is the subject of this token (value of
  /// standard `sub` claim).
  String get subject => _claims['sub'];

  /// Unique identifier of this token (value of standard `jti` claim).
  String get id => _claims['jti'];

  @override
  String toString() {
    var buffer = new StringBuffer();
    buffer.writeAll([encodedHeader, '.', encodedPayload]);
    if (signature is String) {
      buffer.writeAll(['.', signature]);
    }
    return buffer.toString();
  }

  /// Verifies this token's signature using [signer].
  ///
  /// Returns `true` if signature is valid and `false` otherwise.
  bool verify(JWTSigner signer) {
    var body = utf8.encode(encodedHeader + '.' + encodedPayload);
    var sign = base64Url.decode(_base64Padded(signature));
    return signer.verify(body, sign);
  }

  /// Returns value associated with claim specified by [key].
  dynamic getClaim(String key) => _claims[key];
}

/// Builder for JSON Web Tokens.
class JWTBuilder {
  final Map<String, dynamic> _claims = {};

  /// Token issuer (standard `iss` claim).
  void set issuer(String issuer) {
    _claims['iss'] = issuer;
  }

  /// Token audience (standard `aud` claim).
  void set audience(String audience) {
    _claims['aud'] = audience;
  }

  /// Token issued at timestamp in seconds (standard `iat` claim).
  void set issuedAt(DateTime issuedAt) {
    _claims['iat'] = _secondsSinceEpoch(issuedAt);
  }

  /// Token expires timestamp in seconds (standard `exp` claim).
  void set expiresAt(DateTime expiresAt) {
    _claims['exp'] = _secondsSinceEpoch(expiresAt);
  }

  /// Sets value for standard `nbf` claim.
  void set notBefore(DateTime notBefore) {
    _claims['nbf'] = _secondsSinceEpoch(notBefore);
  }

  /// Sets standard `sub` claim value.
  void set subject(String subject) {
    _claims['sub'] = subject;
  }

  void set id(String id) {
    _claims['jti'] = id;
  }

  /// Sets value of private (custom) claim.
  ///
  /// One can not use this method to
  /// set values of standard (reserved) claims, [JWTError] will be thrown in such
  /// case.
  void setClaim(String name, value) {
    if (JWT.reservedClaims.contains(name.toLowerCase())) {
      throw new ArgumentError.value(
          name, 'name', 'Only custom claims can be set with setClaim.');
    }
    _claims[name] = value;
  }

  /// Builds and returns JWT. The token will not be signed.
  ///
  /// To create signed token use [getSignedToken] instead.
  JWT getToken() {
    var headers = {'typ': 'JWT', 'alg': 'none'};
    String encodedHeader = _base64Unpadded(_jsonToBase64Url.encode(headers));
    String encodedPayload = _base64Unpadded(_jsonToBase64Url.encode(_claims));
    return new JWT._(encodedHeader, encodedPayload, null);
  }

  /// Builds and returns signed JWT.
  ///
  /// The token is signed with provided [signer].
  ///
  /// To create unsigned token use [getToken].
  JWT getSignedToken(JWTSigner signer) {
    var headers = {'typ': 'JWT', 'alg': signer.algorithm};
    String encodedHeader = _base64Unpadded(_jsonToBase64Url.encode(headers));
    String encodedPayload = _base64Unpadded(_jsonToBase64Url.encode(_claims));
    var body = encodedHeader + '.' + encodedPayload;
    var signature =
        _base64Unpadded(base64Url.encode(signer.sign(utf8.encode(body))));
    return new JWT._(encodedHeader, encodedPayload, signature);
  }
}

/// Signer interface for JWT.
abstract class JWTSigner {
  String get algorithm;
  List<int> sign(List<int> body);
  bool verify(List<int> body, List<int> signature);
}

/// Signer implementing HMAC encryption using SHA256 hashing.
class JWTHmacSha256Signer implements JWTSigner {
  final List<int> secret;

  JWTHmacSha256Signer(String secret) : secret = utf8.encode(secret);

  @override
  String get algorithm => 'HS256';

  @override
  List<int> sign(List<int> body) {
    var hmac = new Hmac(sha256, secret);
    return hmac.convert(body).bytes;
  }

  @override
  bool verify(List<int> body, List<int> signature) {
    var actual = sign(body);
    if (actual.length == signature.length) {
      // constant-time comparison
      bool isEqual = true;
      for (var i = 0; i < actual.length; i++) {
        if (actual[i] != signature[i]) isEqual = false;
      }
      return isEqual;
    } else
      return false;
  }
}

/// Validator for JSON Web Tokens.
///
/// One must configure validator and provide values for claims that should be
/// validated, except for `iat`, `exp` and `nbf` claims - these are always
/// validated based on the value of [currentTime].
class JWTValidator {
  /// Current time used to validate token's `iat`, `exp` and `nbf` claims.
  final DateTime currentTime;
  String issuer;
  String audience;
  String subject;
  String id;

  /// Creates new validator. One can supply custom value for [currentTime]
  /// parameter, if not the `DateTime.now()` value is used by default.
  JWTValidator({DateTime currentTime})
      : currentTime = currentTime ?? new DateTime.now();

  /// Validates provided [token] and returns a list of validation errors.
  /// Empty list indicates there were no validation errors.
  ///
  /// If [signer] parameter is provided then token signature
  /// will also be verified. Otherwise signature must be verified manually using
  /// [JWT.verify] method.
  Set<String> validate(JWT token, {JWTSigner signer}) {
    var errors = new Set<String>();

    var currentTimestamp = _secondsSinceEpoch(currentTime);
    if (token.expiresAt is int && currentTimestamp >= token.expiresAt) {
      errors.add('The token has expired.');
    }

    if (token.issuedAt is int && currentTimestamp < token.issuedAt) {
      errors.add('The token issuedAt time is in future.');
    }

    if (token.notBefore is int && currentTimestamp < token.notBefore) {
      errors.add('The token can not be accepted due to notBefore policy.');
    }

    if (issuer is String && issuer != token.issuer) {
      errors.add('The token issuer is invalid.');
    }

    if (audience is String && audience != token.audience) {
      errors.add('The token audience is invalid.');
    }

    if (subject is String && subject != token.subject) {
      errors.add('The token subject is invalid.');
    }

    if (id is String && id != token.id) {
      errors.add('The token unique identifier is invalid.');
    }

    if (signer is JWTSigner && !token.verify(signer)) {
      errors.add('The token signature is invalid.');
    }

    return errors;
  }
}
