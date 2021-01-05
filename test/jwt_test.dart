library corsac_jwt.test;

import 'package:corsac_jwt/corsac_jwt.dart';
import 'package:corsac_jwt/src/utils.dart';
import 'package:test/test.dart';

void main() {
  group('$JWT', () {
    DateTime now;
    JWTBuilder builder;

    setUp(() {
      now = DateTime.now();
      builder = JWTBuilder()
        ..issuer = 'https://mycompany.com'
        ..audience = 'people'
        ..issuedAt = now
        ..expiresAt = now.add(Duration(seconds: 10))
        ..notBefore = now.add(Duration(seconds: 5))
        ..id = 'identifier'
        ..subject = 'subj';
    });

    test('JWTError toString', () {
      final error = JWTError('failed');
      expect(error.toString(), 'JWTError: failed');
    });

    test('JWTBuilder can build unsigned token', () {
      final token = builder.getToken();
      expect(token, const TypeMatcher<JWT>());
      expect(token.issuer, equals('https://mycompany.com'));
    });

    test('JWTBuilder can build signed token', () {
      final signer = JWTHmacSha256Signer('secret1');
      final token = builder.getSignedToken(signer);

      expect(token, const TypeMatcher<JWT>());
      expect(token.issuer, equals('https://mycompany.com'));
      expect(token.verify(signer), isTrue);
      expect(token.verify(JWTHmacSha256Signer('invalid')), isFalse);
    });

    test('it parses string token', () {
      final signer = JWTHmacSha256Signer('secret1');
      const stringToken =
          'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL215Y29tcGF'
          'ueS5jb20ifQ.R7OVbiAKtvSkE-qF0fCkZP_m2JGrHobbRayHhEsKuKU';
      final token = JWT.parse(stringToken);

      expect(token, const TypeMatcher<JWT>());
      expect(token.issuer, equals('https://mycompany.com'));
      expect(token.verify(signer), isTrue);
      expect(token.verify(JWTHmacSha256Signer('invalid')), isFalse);
    });

    test('it parses another token', () {
      final signer = JWTHmacSha256Signer('secret');
      const stringToken =
          'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL215Zm9vYmF'
          'yLmNvbSIsImlhdCI6MTQ1NTIzMjI2NywiZXhwIjoxNDU1MjM0MDY3LCJuYmYiOjE0NTU'
          'yMzIyMzcsImJvZHkiOnsiYmxhaCI6ImJvb2EifX0.PXbDbE7YapU-6WvRqbdQ2OC1N2D'
          'ScadvuQUqTHXopNc';

      final token = JWT.parse(stringToken);

      expect(token, const TypeMatcher<JWT>());
      expect(token.issuer, equals('https://myfoobar.com'));
      expect(token.verify(signer), isTrue);
      expect(token.verify(JWTHmacSha256Signer('invalid')), isFalse);
      expect(token.toString(), stringToken);
    });

    test('it throws JWTError if token is invalid', () {
      const badToken1 =
          'invalid.eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL21'
          '5Y29tcGFueS5jb20ifQ.R7OVbiAKtvSkE-qF0fCkZP_m2JGrHobbRayHhEsKuKU';
      const badToken2 = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.invalid';
      expect(
          () => JWT.parse(badToken1), throwsA(const TypeMatcher<JWTError>()));
      expect(
          () => JWT.parse(badToken2), throwsA(const TypeMatcher<JWTError>()));
    });

    test('it supports all standard claims', () {
      final token = builder.getToken();
      expect(token, const TypeMatcher<JWT>());
      expect(token.issuer, equals('https://mycompany.com'));
      expect(token.audience, equals('people'));
      expect(token.issuedAt, equals(secondsSinceEpoch(now)));
      expect(token.expiresAt, equals(secondsSinceEpoch(now) + 10));
      expect(token.notBefore, equals(secondsSinceEpoch(now) + 5));
      expect(token.id, equals('identifier'));
      expect(token.subject, equals('subj'));
      expect(token.algorithm, equals('none'));
    });

    test('it prevents setting standard claims using setClaim', () {
      expect(() => builder.setClaim('iss', 'bad'), throwsArgumentError);
    });

    test('it supports custom (private) claims', () {
      builder
        ..issuer = 'https://foobar.com'
        ..setClaim('pld', 'payload')
        ..setClaim('map', {'key': 'value'});
      final token = builder.getToken();
      expect(token.issuer, equals('https://foobar.com'));
      expect(token.getClaim('pld'), equals('payload'));
      expect(token.getClaim('map'), equals({'key': 'value'}));

      final stringToken = token.toString();
      final parsedToken = JWT.parse(stringToken);

      expect(parsedToken.issuer, equals('https://foobar.com'));
      expect(parsedToken.getClaim('pld'), equals('payload'));
      expect(parsedToken.getClaim('map'), equals({'key': 'value'}));

      final claims = parsedToken.claims;

      expect(claims['pld'], equals('payload'));
      expect(claims['map'], equals({'key': 'value'}));

      claims['pld'] = 'good times!';
      expect(claims['pld'], equals('good times!'));
      expect(parsedToken.getClaim('pld'), equals('payload'));
    });

    test('it supports custom headers', () {
      builder
        ..issuer = 'https://foobar.com'
        ..setHeader('x5t', 'payload');
      final token = builder.getToken();
      expect(token.issuer, equals('https://foobar.com'));
      expect(token.headers['x5t'], equals('payload'));

      final stringToken = token.toString();
      final parsedToken = JWT.parse(stringToken);

      expect(parsedToken.issuer, equals('https://foobar.com'));
      expect(parsedToken.headers['x5t'], equals('payload'));
    });

    test('it throws error for updating reserved headers', () {
      expect(() {
        builder.setHeader('typ', 'error');
      }, throwsArgumentError);
    });

    test('validator uses current time by default', () {
      final validator = JWTValidator();
      expect(validator.currentTime, isNotNull);
    });

    test('iss claim is validated', () {
      final token = builder.getToken();
      final time = DateTime.now().add(Duration(seconds: 6));
      final validator = JWTValidator(currentTime: time)..issuer = 'wrong';
      var errors = validator.validate(token);
      expect(errors, isNotEmpty);
      expect(errors, contains('The token issuer is invalid.'));

      validator.issuer = 'https://mycompany.com';
      errors = validator.validate(token);
      expect(errors, isEmpty);
    });

    test('exp claim is validated', () {
      final token = builder.getToken();
      var validator =
          JWTValidator(currentTime: DateTime.now().add(Duration(seconds: 20)));
      var errors = validator.validate(token);
      expect(errors, isNotEmpty);
      expect(errors, contains('The token has expired.'));

      validator =
          JWTValidator(currentTime: DateTime.now().add(Duration(seconds: 5)));
      errors = validator.validate(token);
      expect(errors, isEmpty);
    });

    test('iat claim is validated', () {
      final token = builder.getToken();

      var validator = JWTValidator(
          currentTime: DateTime.now().subtract(Duration(seconds: 1)));
      var errors = validator.validate(token);
      expect(errors, isNotEmpty);
      expect(errors, contains('The token issuedAt time is in future.'));

      final time = DateTime.now().add(Duration(seconds: 6));
      validator = JWTValidator(currentTime: time);
      errors = validator.validate(token);
      expect(errors, isEmpty);
    });

    test('nbf claim is validated', () {
      final token = builder.getToken();
      var validator =
          JWTValidator(currentTime: DateTime.now().add(Duration(seconds: 1)));
      var errors = validator.validate(token);
      expect(errors, isNotEmpty);
      expect(errors,
          contains('The token can not be accepted due to notBefore policy.'));

      final time = DateTime.now().add(Duration(seconds: 6));
      validator = JWTValidator(currentTime: time);
      errors = validator.validate(token);
      expect(errors, isEmpty);
    });

    test('aud claim is validated', () {
      final token = builder.getToken();
      final time = DateTime.now().add(Duration(seconds: 6));
      final validator = JWTValidator(currentTime: time)..audience = 'wrong';
      var errors = validator.validate(token);
      expect(errors, isNotEmpty);
      expect(errors, contains('The token audience is invalid.'));

      validator.audience = 'people';
      errors = validator.validate(token);
      expect(errors, isEmpty);
    });

    test('sub claim is validated', () {
      final token = builder.getToken();
      final time = DateTime.now().add(Duration(seconds: 6));
      final validator = JWTValidator(currentTime: time)..subject = 'wrong';
      var errors = validator.validate(token);
      expect(errors, isNotEmpty);
      expect(errors, contains('The token subject is invalid.'));

      validator.subject = 'subj';
      errors = validator.validate(token);
      expect(errors, isEmpty);
    });

    test('jti claim is validated', () {
      final token = builder.getToken();
      final time = DateTime.now().add(Duration(seconds: 6));
      final validator = JWTValidator(currentTime: time)..id = 'wrong';
      var errors = validator.validate(token);
      expect(errors, isNotEmpty);
      expect(errors, contains('The token unique identifier is invalid.'));

      validator.id = 'identifier';
      errors = validator.validate(token);
      expect(errors, isEmpty);
    });

    test('signature is validated', () {
      final signer = JWTHmacSha256Signer('secret');

      final token = builder.getSignedToken(signer);
      final time = DateTime.now().add(Duration(seconds: 6));
      final validator = JWTValidator(currentTime: time);
      var errors =
          validator.validate(token, signer: JWTHmacSha256Signer('invalid'));
      expect(errors, isNotEmpty);
      expect(errors, contains('The token signature is invalid.'));

      errors = validator.validate(token, signer: signer);
      expect(errors, isEmpty);
    });

    test('it provides read-only access to headers', () {
      builder.issuer = 'https://foobar.com';
      final token = builder.getToken();

      final headers = token.headers;
      expect(headers['typ'], 'JWT');
      expect(headers['alg'], 'none');
      expect(() {
        headers['kid'] = 'boom';
      }, throwsUnsupportedError);
    });
  });
}
