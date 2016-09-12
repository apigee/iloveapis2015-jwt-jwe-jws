# jwe callout

This directory contains the Java source code and pom.xml file required
to compile a Java callout for Apigee Edge that creates and decrypts JWE
. It uses the Jose4J library for JOSE (JSON Object Signing and
Encryption) support.

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
     jose4j-0.4.4.jar

4. be sure to include a Java callout policy in your
   apiproxy/resources/policies directory. It should look like
   this:
    ```xml
    <JavaCallout name='JavaCallout-JWE-Encrypt-A128CBC-HS256'>
      <Properties>...</Properties>
      <ClassName>com.apigee.callout.jwe.JweEncryptorCallout</ClassName>
      <ResourceURL>java://jwe-edge-callout.jar</ResourceURL>
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
 - Jose4J v0.4.4

All these jars must be available on the classpath for the compile to
succeed. The build.sh script should download all of these files for
you, automatically.



Configuring the Callout Policy:
----------------------------

There are two callout classes, one to generate a JWE and one to decrypt
a JWE. 

How the JWE is generated or decrypted, respectively,
depends on configuration information you specify for the callout, in the
form of properties on the policy.  Some examples follow. 



**Encrypting arbitrary data with A128CBC-HS256**

```xml
<JavaCallout name='JavaCallout-JWE-Encrypt-A128CBC-HS256' >
  <Properties>
    <Property name="algorithm">A128CBC-HS256</Property>
    <Property name='secret-key'>{request.formparam.key}</Property>
    <Property name='plaintext'>{request.formparam.plaintext}</Property>
  </Properties>

  <ClassName>com.apigee.callout.jwe.JweEncryptorCallout</ClassName>
  <ResourceURL>java://jwe-edge-callout.jar</ResourceURL>
</JavaCallout>
```

The list of supported encryption algorithms is: 
-A128CBC-HS256
-A192CBC-HS384
-A256CBC-HS512
-A128GCM
-A192GCM
-A256GCM

For information on the meaning of these algorithms, see section 5 of the JWS spec: 
https://tools.ietf.org/html/rfc7518. 


**Decrypting a JWE**

```xml
<JavaCallout name='JavaCallout-JWE-Decrypt-A128CBC-HS256' >
  <Properties>
    <Property name="algorithm">A128CBC-HS256</Property>
    <Property name='secret-key'>{request.formparam.key}</Property>
    <Property name='jwe'>{request.formparam.jwe}</Property>
  </Properties>

  <ClassName>com.apigee.callout.jwe.JweDecryptorCallout</ClassName>
  <ResourceURL>java://jwe-edge-callout.jar</ResourceURL>
</JavaCallout>
```

Any of {algorithm, secret-key, and jwe} may be referenced as static strings,
variables wrapped in curlies, or compound strings composed of 1 or more variables
and static strings. For example, "ABC-{secret}" will resolve to "ABC-123" if the
context variable "secret" resolves to "123".

For decryption, the JWE includes the algorithm that must be used for decryption.  If you specify an algorithm property, then the callout verifies that the algorithm included in the JWE matches the one provided in the property. If you do not specify an algorithm property, then the JWE Decryptor callout does not verify that the algorithm is any particular value. This is probably not what you want, but in some cases it might be.


More Notes:
--------

- This callout does not currently support JWE with RSA encryption
- This callout always uses PBES2-HS256+A128KW to derive symmetric keys. 




