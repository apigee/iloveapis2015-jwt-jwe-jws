# jwt_signed callout

This directory contains the Java source code and Java jars required to
compile a Java callout for Apigee Edge that does generation and
parsing / validation of signed JWT. It uses the Nimbus library for JOSE. 

Building:
--------

You can use the Java callout binary, or you can build the binary yourself. 
These instructions describe how to do either. 

1. unpack (if you can read this, you've already done that).

2. build the binary with maven:  
   ```
   mvn clean package
   ```

3. maven will copy all the required jar files to your apiproxy/resources/java directory. 
   If for some reason your project directory is not set up properly, you can do this manually. 
   copy target/jwt-edge-callout.jar to your apiproxy/resources/java directory. 
   Also copy from the target/lib directory, these jars:  
     json-smart-1.3.jar
     nimbus-jose-jwt-3.1.2.jar
     guava-18.0.jar

4. be sure to include a Java callout policy in your
   apiproxy/resources/policies directory. It should look like
   this:
    ```xml
    <JavaCallout name="JavaJwtHandler" enabled='true'
                 continueOnError='false' async='false'>
      <DisplayName>Java JWT Creator</DisplayName>
      <Properties>...</Properties>
      <ClassName>com.apigee.callout.jwt.JwtCreatorCallout</ClassName>
      <ResourceURL>java://jwt-edge-callout.jar</ResourceURL>
    </JavaCallout>
   ```

5. Deploy your API Proxy, using 
   pushapi (See https://github.com/carloseberhardt/apiploy)
   or a similar alternative tool.



Dependencies
------------------

Jars available in Edge:   
 - Apigee Edge expressions v1.0
 - Apigee Edge message-flow v1.0
 - Apache commons lang v2.6 - String and Date utilities
 - Apache commons codec 1.7 - Base64 decoder
 - not-yet-commons-ssl v0.3.9 - RSA private/public crypto

Jars not available in Edge:
 - Nimbus JOSE JWT v3.1.2
 - json-smart v1.3
 - Google Guava 18.0 (for collections utilities)

All these jars must be available on the classpath for the compile to
succeed. The build.sh script should download all of these files for
you, automatically.

**Manual Download of Depencencies?**

Maven will download all of these dependencies for you. If you wish to download them manually: 

The first 5 jars are available in Apigee Edge. 

The first two are
produced by Apigee; contact Apigee support to obtain these jars to allow
the compile, or get them here: 
https://github.com/apigee/api-platform-samples/tree/master/doc-samples/java-cookbook/lib

The Apache Commons Lang and Codec jar is shipped by the Apache
Software Foundation. You need the versions specified here, because
that is what Apigee Edge currently uses.
    http://commons.apache.org/proper/commons-lang/
    http://commons.apache.org/proper/commons-codec/

not-yet-commons-ssl 
    http://juliusdavies.ca/commons-ssl/download.html

v3.1.2 jar for Nimbus Jose JWT 
    http://connect2id.com/products/nimbus-jose-jwt

v1.3 JSON Smart 
    http://mvnrepository.com/artifact/net.minidev/json-smart

v18.0 of Google Guava 
    http://central.maven.org/maven2/com/google/guava/guava/18.0/guava-18.0.jar


Configuring the Callout Policy:
--------

There are two callout classes, one to generate a JWT and one to validate
and parse a JWT. How the JWT is generated or validated, respectively,
depends on configuration information you specify for the callout, in the
form of properties on the policy.  Some examples follow. 

**Generate a JWT using HS256**
```xml
  <JavaCallout name='JavaCallout-JWT-Create' enabled='true'>
    <DisplayName>JavaCallout-JWT-Create</DisplayName>
    <Properties>
      <Property name="algorithm">HS256</Property>
      <!-- the key is likely the client_secret -->
      <Property name="key">{organization.name}</Property>
      <!-- claims -->
      <Property name="subject">{apiproxy.name}</Property>
      <Property name="issuer">http://dinochiesa.net</Property>
      <Property name="audience">{desired_jwt_audience}</Property>
      <Property name="expiresIn">86400</Property> <!-- in seconds -->
    </Properties>

    <ClassName>com.apigee.callout.jwt.JwtCreatorCallout</ClassName>
    <ResourceURL>java://jwt-edge-callout.jar</ResourceURL>
  </JavaCallout>
```

This class conjures a JWT with the standard claims: 
 - subject (sub)  
 - audience (aud)  
 - issuer (iss)  
 - issuedAt (iat)  
 - expiration (exp)  
 - id (jti)  

It uses HMAC-SHA256 for signing. 

The values for the properties can be specified as string values, or
as variables to de-reference, when placed inside curly braces.

It emits the dot-separated JWT into the variable named
    jwt_jwt

There is no way to explicitly set the "issued at" (iat) time.  The iat
time automatically gets the value accurately indicating when the JWT is
generated.


**Generate a JWT using RS256**

To generate a key signed with RS256, you can specify the private RSA key inside the policy configuration, like this:

```xml
  <JavaCallout name='JavaCallout-JWT-Create-RS256-2' >
    <DisplayName>JavaCallout-JWT-Create-RS256-2</DisplayName>
    <Properties>
      <Property name="algorithm">RS256</Property>

      <!-- private-key and private-key-password used only for algorithm = RS256 -->
      <Property name="private-key">
      -----BEGIN RSA PRIVATE KEY-----
      Proc-Type: 4,ENCRYPTED
      DEK-Info: DES-EDE3-CBC,049E6103F40FBE84

      EZVWs5v4FoRrFdK+YbpjCmW0KoHUmBAW7XLvS+vK3BdSM2Yx/hPhDO9URCVl9Oar
      ApEZC1CxzsyRfvKDtiKWfQKdYKLccl8pA4Jj0sCxVgL4MBFDNDDEau4vRfXBv2EF
      ....
      7ZOF1UXVaoldDs+izZo5biVF/NNIBtg2FkZd4hh/cFlF1PV+M5+5mA==
      -----END RSA PRIVATE KEY-----
      </Property>

      <!-- this value should not be hardcoded. Put it in the vault! -->
      <Property name="private-key-password">deecee123</Property>

      <!-- standard claims -->
      <Property name="subject">{apiproxy.name}</Property>
      <Property name="issuer">http://dinochiesa.net</Property>
      <Property name="audience">Optional-String-or-URI</Property>
      <Property name="expiresIn">86400</Property> <!-- in seconds -->

      <!-- custom claims to inject into the JWT -->
      <Property name="claim_primarylanguage">English</Property>
      <Property name="claim_shoesize">8.5</Property>

    </Properties>

    <ClassName>com.apigee.callout.jwt.JwtCreatorCallout</ClassName>
    <ResourceURL>java://jwt-edge-callout.jar</ResourceURL>
  </JavaCallout>
```

The private key need not be encrypted. If it is, obviously you need to
specify the private-key-password. That password can be (should be!) a variable - specify it in curly braces in that case. You should retrieve it from secure storage before invoking this policy. 

The resulting JWT is signed with RSA, using the designated private-key. 


**Generate a JWT using RS256 - specify PEM file as resource in JAR**

You can also specify the PEM as a named file resource that is bundled in the jar itself. To do this, you need to recompile the jar with your desired pemfile contained within it. The class looks for the file in the jarfile under the /resources directory. The configuration looks like this:

```xml
  <JavaCallout name='JavaCallout-JWT-Create'>
    <DisplayName>JavaCallout-JWT-Create</DisplayName>
    <Properties>
      <Property name="algorithm">RS256</Property>

      <!-- pemfile + private-key-password} used only for algorithm = RS256 -->
      <Property name="pemfile">private.pem</Property>
      <Property name="private-key-password">{var.that.contains.password.here}</Property>

      <!-- claims to inject into the JWT -->
      <Property name="subject">{apiproxy.name}</Property>
      <Property name="issuer">http://dinochiesa.net</Property>
      <Property name="audience">{context.var.that.contains.audience.name}</Property>
      <Property name="expiresIn">86400</Property> <!-- in seconds -->

    </Properties>

    <ClassName>com.apigee.callout.jwt.JwtCreatorCallout</ClassName>
    <ResourceURL>java://jwt-edge-callout.jar</ResourceURL>
  </JavaCallout>
```

The pemfile need not be encrypted. If it is, obviously you need to
specify the password .  The file must be in PEM format, not DER
format. The class looks for the file in the jarfile under the /resources
directory.


**Generating a JWT with custom claims**

If you wish to embed other claims into the JWT, you can do so by using
the Properties elements, like this: 

```xml
  <JavaCallout name='JavaCallout-JWT-Create'>
    <DisplayName>JavaCallout-JWT-Create</DisplayName>
    <Properties>
      <Property name="algorithm">RS256</Property>

      <!-- pemfile + private-key-password} used only for algorithm = RS256 -->
      <Property name="pemfile">private.pem</Property>
      <Property name="private-key-password">deecee123</Property>

      <!-- standard claims to embed -->
      <Property name="subject">{apiproxy.name}</Property>
      <Property name="issuer">http://dinochiesa.net</Property>
      <Property name="audience">Optional-String-or-URI</Property>
      <Property name="expiresIn">86400</Property> <!-- in seconds -->

      <!-- custom claims to embed in the JWT. -->
      <!-- Property names must begin with claim_ . -->
      <Property name="claim_shoesize">9</Property>
      <Property name="claim_gender">M</Property>

    </Properties>

    <ClassName>com.apigee.callout.jwt.JwtCreatorCallout</ClassName>
    <ResourceURL>java://jwt-edge-callout.jar</ResourceURL>
  </JavaCallout>
```


**Parsing and Verifying a JWT - HS256**

For parsing and verifying a JWT, you need to specify a different Java class. Configure it like so for HS256: 

```xml
  <JavaCallout name='JavaCallout-JWT-Parse'>
    <DisplayName>JavaCallout-JWT-Parse</DisplayName>
    <Properties>
      <Property name="algorithm">HS256</Property>

      <Property name="jwt">{request.formparam.jwt}</Property>

      <!-- name of var that holds the shared key (likely the client_secret) -->
      <Property name="key">{organization.name}</Property>

    </Properties>

    <ClassName>com.apigee.callout.jwt.JwtParserCallout</ClassName>
    <ResourceURL>java://jwt-edge-callout.jar</ResourceURL>
  </JavaCallout>
```

This class accepts a signed JWT in dot-separated format, verifies the
signature with the specified key, and then parses the resulting claims. 

It sets these context variables: 

      jwt_claims - a json-formatted string of all claims
      jwt_issuer
      jwt_audience
      jwt_subject
      jwt_issueTime
      jwt_issueTimeFormatted ("yyyy-MM-dd'T'HH:mm:ss.SSSZ")
      jwt_expirationTime
      jwt_expirationTimeFormatted
      jwt_secondsRemaining
      jwt_timeRemainingFormatted   (HH:mm:ss.xxx)
      jwt_isExpired  (true/false)
      jwt_isValid  (true/false)


The "Formatted" versions of the times are for diagnostic or display
purposes. It's easier to understand a time when displayed that way. 

The isValid indicates whether the JWT should be honored - true if and
only if the signature verifies and the times are valid, and all the required claims match.

**Parsing and Verifying a JWT - RS256**

To parse and verify a RS256 JWT, then you need to use a configuration like this:

```xml
  <JavaCallout name='JavaCallout-JWT-Parse-RS256-2'>
    <DisplayName>JavaCallout-JWT-Parse-RS256-2</DisplayName>
    <Properties>
      <Property name="algorithm">RS256</Property>
      <Property name="jwt">{request.formparam.jwt}</Property>

      <!-- public-key used only for algorithm = RS256 -->
      <Property name="public-key">
      -----BEGIN PUBLIC KEY-----
      MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtxlohiBDbI/jejs5WLKe
      Vpb4SCNM9puY+poGkgMkurPRAUROvjCUYm2g9vXiFQl+ZKfZ2BolfnEYIXXVJjUm
      zzaX9lBnYK/v9GQz1i2zrxOnSRfhhYEb7F8tvvKWMChK3tArrOXUDdOp2YUZBY2b
      sl1iBDkc5ul/UgtjhHntA0r2FcUE4kEj2lwU1di9EzJv7sdE/YKPrPtFoNoxmthI
      OvvEC45QxfNJ6OwpqgSOyKFwE230x8UPKmgGDQmED3PNrio3PlcM0XONDtgBewL0
      3+OgERo/6JcZbs4CtORrpPxpJd6kvBiDgG07pUxMNKC2EbQGxkXer4bvlyqLiVzt
      bwIDAQAB
      -----END PUBLIC KEY-----
      </Property>

      <!-- claims to verify. Can include custom claims. -->
      <Property name="claim_iss">http://dinochiesa.net</Property>
      <Property name="claim_shoesize">8.5</Property>

    </Properties>

    <ClassName>com.apigee.callout.jwt.JwtParserCallout</ClassName>
    <ResourceURL>java://jwt-edge-callout.jar</ResourceURL>
  </JavaCallout>
```

By default, the Parser callout, whether using HS256 or RS256, verifies
that the NBF and EXP are valid - in other words the JWT is within it's
documented valid time range. You may wish to verify other arbitrary
claims on the JWT .  At this time the only supported check is for
string equivalence.  So you may verify the issuer, the audience, or
the value of any custom custom claim (either public/registered, or
private).

Regarding audience - the spec states that the audience is an array of
strings. The parser class validates that the audience value you pass
here (as a string) is present as one of the elements in that array.
Currently there is no way to verify that the JWT is directed to more
than one audience. To do so, you could invoke the Callout twice, with different
configurations.


**Parse a JWT, and Verify specific claims**

To verify specific claims in the JWT, use additional properties.
Do this by specifying Property elements with name attributes that begin with claim_ :

```xml
  <JavaCallout name='JavaCallout-JWT-Parse'>
    <DisplayName>JavaCallout-JWT-Parse</DisplayName>
    <Properties>
      <Property name="algorithm">RS256</Property>

      <!-- name of var that holds the jwt -->
      <Property name="jwt">{request.formparam.jwt}</Property>

      <!-- name of the pemfile. This must be a resource in the JAR! 
      <Property name="pemfile">rsa-public.pem</Property>

      <!-- specific claims to verify, and their required values. -->
      <Property name="claim_sub">A6EE23332295D597</Property>
      <Property name="claim_aud">http://example.com/everyone</Property>
      <Property name="claim_iss">urn://edge.apigee.com/jwt</Property>
      <Property name="claim_shoesize">9</Property>

    </Properties>

    <ClassName>com.apigee.callout.jwt.JwtParserCallout</ClassName>
    <ResourceURL>java://jwt-edge-callout.jar</ResourceURL>
  </JavaCallout>
```

All the context variables described above are also set in this scenario.

As above, the isValid variable indicates whether the JWT should be
honored. In this case, though, it is true if and only if the times
are valid AND if all of the claims listed as required in the
configuration are present in the JWT, and their respective values
are equal to the values provided in the <Property> elements.

To specify required claims, you must use the claim names as used within the JSON-serialized JWT.  Hence "claim_sub" and "claim_iss", not "claim_subject" and
"claim_issuer".

Verifying specific claims works whether the algorithm is HS256 or RS256.


**Parsing and Verifying a JWT - RS256 - pemfile**

You can also specify the public key as a named file resource in the jar.
To do this, you need to recompile the jar with your desired pemfile contained within it. The class looks for the file in the jarfile under the /resources directory. The configuration looks like this:

```xml
  <JavaCallout name='JavaCallout-JWT-Parse'>
    <DisplayName>JavaCallout-JWT-Parse</DisplayName>
    <Properties>
      <Property name="algorithm">RS256</Property>

      <Property name="jwt">{request.formparam.jwt}</Property>

      <!-- name of the pemfile. This must be a resource in the JAR. -->
      <Property name="pemfile">rsa-public.pem</Property>

    </Properties>

    <ClassName>com.apigee.callout.jwt.JwtParserCallout</ClassName>
    <ResourceURL>java://jwt-edge-callout.jar</ResourceURL>
  </JavaCallout>
```

**Parsing and Verifying a JWT - RS256 - certificate**

You can also specify a serialized X509 certificate which contains the public key. 

```xml
  <JavaCallout name='JavaCallout-JWT-Parse-RS256-3'>
    <DisplayName>JavaCallout-JWT-Parse-RS256-3</DisplayName>
    <Properties>
      <Property name="algorithm">RS256</Property>
      <Property name="jwt">{request.formparam.jwt}</Property>

      <!-- certificate used only for algorithm = RS256 -->
      <Property name="certificate">
      -----BEGIN CERTIFICATE-----
      MIIC4jCCAcqgAwIBAgIQ.....aKLWSqMhozdhXsIIKvJQ==
      -----END CERTIFICATE-----
      </Property>

      <!-- claims to verify -->
      <Property name="claim_iss">https://sts.windows.net/fa2613dd-1c7b-469b-8f92-88cd26856240/</Property>
      <Property name="claim_ver">1.0</Property>

    </Properties>

    <ClassName>com.apigee.callout.jwt.JwtParserCallout</ClassName>
    <ResourceURL>java://jwt-edge-callout.jar</ResourceURL>
  </JavaCallout>
```

This particular example verifies the issuer is a given URL from windows.net.  This is what Azure Active Directory uses when generating JWT. (This URL is unique to the Active Directory instance, so it is not re-usable when verifying your own AAD-generated tokens.) 

If you specify both the public-key and the certificate in the configuration, the public-key will be used and the certificate will be ignored. 
The serialized version of the certificate can include line-breaks and spaces.


More Notes:
--------

- This callout does not support JWT with encrypted claim sets. 
- This callout does not support ES256 algorithms


