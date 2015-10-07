# jwe callout

This directory contains the Java source code and pom.xml file required to
compile a Java callout for Apigee Edge that creates and decrypts JWE generation and
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
     jose4j-0.4.4.jar

4. be sure to include a Java callout policy in your
   apiproxy/resources/policies directory. It should look like
   this:
    ```xml
<JavaCallout name='JavaCallout-JWE-Encrypt-A128CBC-HS256' >
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


More Notes:
--------

- This callout does not currently support JWE with RSA encryption



