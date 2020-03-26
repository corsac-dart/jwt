import 'package:corsac_jwt/corsac_jwt.dart';
import 'package:test/test.dart';
import 'dart:io';

void main() {
  group('RS256: ', () {
    JWTRsaSha256Signer signer;
    setUp(() {
      var priv = new File('test/resources/private.pem').readAsStringSync();
      var pub = new File('test/resources/public.pem').readAsStringSync();
      signer = new JWTRsaSha256Signer(privateKey: priv, publicKey: pub);
    });

    test('it can sign and verify JWT with RS256', () {
      var builder = new JWTBuilder();
      builder
        ..issuer = 'abc.com'
        ..expiresAt = new DateTime.now().add(new Duration(minutes: 3));
      var token = builder.getSignedToken(signer);

      expect(token.algorithm, 'RS256');
      expect(token.verify(signer), isTrue);
    });

    test('it handles exceptions on verification', () {
      var jwtString = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.'
          'eyJpZCI6ImY0MTJiMDViZTRhYTIwZmJlNmEwMDUyZjA5YjdlMzhjOTlmYjdhNjEiLCJqdGkiOiJmNDEyYjA1YmU0YWEyMGZiZTZhMDA1MmYwOWI3ZTM4Yzk5ZmI3YTYxIiwiaXNzIjoiaHR0cDovL2FwaS5mb29iYXIuY29tIn0.'
          'B2vu-KIEFvY3T_EPAYFw48OS7Q7kKVbbOSMIhptyIHZximJ6hkFCBTr2Czz5ArbEYJfAL8_3ZtV3Il6YxE5XQF5hVFNet-Ypt-RzRXPtKMAqt_iiu4C4qg7qes9penNHgu2hvZbQ2FpSPGKrt_ozNehy52YysAKmzKj2ZSelru81ap80pgkYC6Eql8DGIqgz6OVHj_9NRQHqJ2OHDi_nLjYSQW6BtKSA-nmaySr_wn2rMe2xSaf2iA3mPiheCN6yL8yvwcGziNX3wtyahuL1vxg_wJ-sD-py9X7bLu9OmoWds76gxAQQh0Wi694FXQ5p5e4ub0BDlJ9Pv2vr2uPzKL6OQpY4wYBYNhe4UF2QxfFjwnYWITo6O6_tiQtH7Q6WNqF27OfriGYNQbiOgD0icpRrL9w3JI907G4bO3bm0mCIimBbLgr0B_pM4Pr5wcbhXC71yZ0j3ODlfXJ9qnO9G5aAGC9wwFsGT0jgv0ydReDwMgasMN4lYl_iUkxckhHR6ys3wg8FG6SG818CvG-jOkrJMIjNXD9nZMVXPH-tqP-8_60SN8G5vPVdB0nxwL6FprWIc6jC-eXPsATN4E4YJnu5Wnsd4VEPKZVX4Q1AFVOO6dgDxZ7jGStHx50Q1zh1GuNIeEmSnWsVsgtkhTymyZNQSvoIiZnq-wcNtB-YFvY';
      var token = new JWT.parse(jwtString);
      expect(token.verify(signer), isFalse);
    });
  });
}
