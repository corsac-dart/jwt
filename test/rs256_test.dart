import 'dart:io';

import 'package:corsac_jwt/corsac_jwt.dart';
import 'package:test/test.dart';

void main() {
  group('RS256: ', () {
    JWTRsaSha256Signer signer;
    setUp(() {
      final priv = File('test/resources/private.pem').readAsStringSync();
      final pub = File('test/resources/public.pem').readAsStringSync();
      signer = JWTRsaSha256Signer(privateKey: priv, publicKey: pub);
    });

    test('it can sign and verify JWT with RS256', () {
      final builder = JWTBuilder()
        ..issuer = 'abc.com'
        ..expiresAt = DateTime.now().add(Duration(minutes: 3));
      final token = builder.getSignedToken(signer);

      expect(token.algorithm, 'RS256');
      expect(token.verify(signer), isTrue);
    });

    test('it handles exceptions on verification', () {
      const jwtString = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.'
          'eyJpZCI6ImY0MTJiMDViZTRhYTIwZmJlNmEwMDUyZjA5YjdlMzhjOTlmYjdhNjEiLCJq'
          'dGkiOiJmNDEyYjA1YmU0YWEyMGZiZTZhMDA1MmYwOWI3ZTM4Yzk5ZmI3YTYxIiwiaXNz'
          'IjoiaHR0cDovL2FwaS5mb29iYXIuY29tIn0.'
          'B2vu-KIEFvY3T_EPAYFw48OS7Q7kKVbbOSMIhptyIHZximJ6hkFCBTr2Czz5ArbEYJfA'
          'L8_3ZtV3Il6YxE5XQF5hVFNet-Ypt-RzRXPtKMAqt_iiu4C4qg7qes9penNHgu2hvZbQ'
          '2FpSPGKrt_ozNehy52YysAKmzKj2ZSelru81ap80pgkYC6Eql8DGIqgz6OVHj_9NRQHq'
          'J2OHDi_nLjYSQW6BtKSA-nmaySr_wn2rMe2xSaf2iA3mPiheCN6yL8yvwcGziNX3wtya'
          'huL1vxg_wJ-sD-py9X7bLu9OmoWds76gxAQQh0Wi694FXQ5p5e4ub0BDlJ9Pv2vr2uPz'
          'KL6OQpY4wYBYNhe4UF2QxfFjwnYWITo6O6_tiQtH7Q6WNqF27OfriGYNQbiOgD0icpRr'
          'L9w3JI907G4bO3bm0mCIimBbLgr0B_pM4Pr5wcbhXC71yZ0j3ODlfXJ9qnO9G5aAGC9w'
          'wFsGT0jgv0ydReDwMgasMN4lYl_iUkxckhHR6ys3wg8FG6SG818CvG-jOkrJMIjNXD9n'
          'ZMVXPH-tqP-8_60SN8G5vPVdB0nxwL6FprWIc6jC-eXPsATN4E4YJnu5Wnsd4VEPKZVX'
          '4Q1AFVOO6dgDxZ7jGStHx50Q1zh1GuNIeEmSnWsVsgtkhTymyZNQSvoIiZnq-wcNtB-Y'
          'FvY';
      final token = JWT.parse(jwtString);
      expect(token.verify(signer), isFalse);
    });
  });
}
