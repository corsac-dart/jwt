## 2.0.0

- Switched to package:jose for key parsing, signing and verification logic
- Added ES256 signer
- Removed no longer used dependencies
- Breaking change: the RS256 signer constructor, changed:
  ```
  // from:
  JWTRsaSha256Signer({String? privateKey, String? publicKey, String? password, String? kid})
  // to:
  JWTRsaSha256Signer({required String pem, String? kid})
  ```
  The `password` argument was never implemented by the underlying package so removed to avoid confusion.
  The single `pem` param now can be used to represent either the private key or public key.

## 1.0.1

- Internal changes.

## 1.0.0

- Allow setting `kid` header from signers.
- Allow setting standard `typ` header from builder.

## 1.0.0-nullsafety.1

- Support null safety (#21)

## 0.4.0

- Allow setting custom headers. See `JWTBuilder.setHeader` for details.

## 0.3.0

- Upgraded dependencies.

## 0.2.2

- Upgraded dependencies which fixes an issue with validating Firebase id tokens.

## 0.2.1

- Added getter to access headers map (read-only).

## 0.2.0

- Added back RS256 signer (#11)

## 0.1.2

- Exposed complete `claims` Map (read-only).

## 0.1.1

- Relaxed SDK constraint to allow 2.0.0-dev versions.

## 0.1.0

- Initial release.
