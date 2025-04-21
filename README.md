Lightweight implementation of JSON Web Tokens (JWT).

## Usage

```dart
import 'package:corsac_jwt/corsac_jwt.dart';

void main() {
  var builder = new JWTBuilder();
  var token = builder
    ..issuer = 'https://api.foobar.com'
    ..expiresAt = new DateTime.now().add(new Duration(minutes: 3))
    ..setClaim('data', {'userId': 836})
    ..getToken(); // returns token without signature

  var signer = new JWTHmacSha256Signer('sharedSecret');
  var signedToken = builder.getSignedToken(signer);
  print(signedToken); // prints encoded JWT
  var stringToken = signedToken.toString();

  var decodedToken = new JWT.parse(stringToken);
  // Verify signature:
  print(decodedToken.verify(signer)); // true

  // Validate claims:
  var validator = new JWTValidator() // uses DateTime.now() by default
    ..issuer = 'https://api.foobar.com'; // set claims you wish to validate
  Set<String> errors = validator.validate(decodedToken);
  print(errors); // (empty list)
}
```

Supported signers:

* HS256 (`JWTHmacSha256Signer`).
* RS256 (`JWTRsaSha256Signer`)
* ES256 (`JWTEcdsaSha256Signer`)

Refer to documentation for more details.

## License

BSD-2
