# JWT - Encrypted

This api proxy creates and validates encrypted JWT, aka JSON Web Tokens.
JWT is an IETF standard.
https://tools.ietf.org/html/rfc7519


Apigee Edge doesn't currently contain "native" capability to create or
verify an encrypted JWT.  This proxy shows how to use a Java callout to do those
things.

....

## JWT (encrypted) API Proxy

This directory contains Java source code for a callout which verifies and creates an encrypted JWT,
as well as an example API proxy, which shows how to use the callout.


- [Java source](callout) - Java code, as well as a pom.xml file that allows you to build the Java code with maven.

- [API Proxy](apiproxy) - The apiproxy subdirectory here includes the API proxy configuration, which demonstrates the Java callout. Therefore you do not need to build the Java code in order to use this JWT verifier example. However, you will want to modify this code for your own purposes. After modifying the code, re-build, then copy that JAR into the appropriate apiproxy/resources/java directory for the API Proxy.  You can do the building and copying with the maven pom.xml file. 


## The use of Private and Public Keys

1) The JWT is created by JWE standards using the public key to encrypt. 

2) Conversely, at the time of verification the JWT is decrypted using the private key.

3) For this particular implementation it is assumed that that we will maintain the public key - private key pair per application (by API Key).


## Setup of the example

The example API proxy, during verification, retrieves a private key and the password for the private key from the Apigee vault. This is done via the node.js target, which uses the apigee-access module. Therefore, in order to run the example, you must place those required values into the vault. Also, you need to create an API Product, a developer, and a developer app; and the developer app must have a custom attribute that contains the public key. 

This repo contains a provisioning script to assist. Run it like this: 

```
./provision.sh -o ORGNAME -e ENVNAME -n -f keys/key1-private-encrypted.pem -p secret123 -b keys/key1-public.pem -b keys/key1-public.pem  
```

The Apigee Vault documentation can be found here - http://apigee.com/docs/api-reference/api/vaults


## Switching to a different Private / Public key pair

You can, of course, modify the example to use a different key pair. In that case you need to modify the JWT_Encrypted_Creator_Callout.xml policy to specify the public key you will use.  Also use the provision.sh script to specify the encrypted private key file (pem encoded). 


## Example API calls 

1) Create an encrypted JWT 

This is a sample request: 

```
curl -i -X POST -d '' \
  'http://iloveapis2015-test.apigee.net/jwt_encrypted/create?apikey=API_KEY_HERE'
```


A sample response:
 
```
{
  "jwt": "eyJhbGciOiJSU0EtT0FFUC.....y3AAmfG5VKQ"
}
```

2) Verify (decrypt and verify) an encrypted JWT

This is a sample request: 

```
curl -X POST -H "Content-Type: application/x-www-form-urlencoded" \
   'http://iloveapis2015-test.apigee.net/jwt_encrypted/validate?apikey=API_KEY_HERE' \
  -d 'jwt=eyJhbGciOiJSU0EtT0FFUC0y.....AAmfG5VKQ' 
```


A sample response:

```
{
  "jwt": "eyJhbGci............ty3AAmfG5VKQ",
  "claims": {
    "iss": "Xmzm0xlH27YerSdWzk78Gf3QHaP1WyQd",
    "exp": 1444717120,
    "jti": "d0b91351-0cbe-4fad-8fe2-9a7a63e6fb4c",
    "sub": "users",
    "email": "users@test.com",
    "Country": "USA",
    "active": "true",
    "dealerId": "1234",
    "url": "www.mycompany.com"
  },
  "isExpired": "false"
}
```


# Build and Deploy 

The provision.sh script mentioned earlier deploys this proxy. 

You can also use apigeetool or maven to deploy this proxy.

This project is already set up with maven (parent and project pom.xml's).

All you need to do is to run the following maven command from the same folder that contains the toplevel pom.xml 

```
mvn install -P {apigee_environment} \
  -Dusername={YOUR_EDGE_USER_NAME} \
  -Dpassword={YOUR_EDGE_PASSWORD} \
  -Dorg={} -DskipTests=true \
  -Dapigee.options=validate,update
```



