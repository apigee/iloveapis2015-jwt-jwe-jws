JWT- Encrypted
=============

This api proxy creates and validates encrypted JWT, aka JSON Web Tokens.
JWE is an IETF standard.
https://tools.ietf.org/html/rfc7516



Apigee Edge doesn't currently contain "native" capability to create or
verify an encrypted JWT.  This proxy shows how to use a Java callout to do those
things.

....

# JWT (encrypted) API Proxy

This directory contains Java source code for a callout which verifies and creates an encrypted JWT,
as well as an example API proxy, which shows how to use the callout.


- [Java source](callout) - Java code, as well as instructions for how to build the Java code.

The API Proxy subdirectory here includes the pre-built JAR file. Therefore you do not need to build the Java code in order to use this JWT verifier. However, you may wish to modify this code for your own purposes. In that case, you will modify the Java code, re-build, then copy that JAR into the appropriate apiproxy/resources/java directory for the API Proxy.

# JWT Encrypted sample API calls -

1) Create an encrypted JWT 

REQUEST - 
curl -X POST  
'http://iloveapis2015-test.apigee.net/jwt_encrypted/create?apikey={apiKey}'

RESPONSE - 
{
  "jwt": "eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.RaFg8gIz4TdDM9IzJAWIGmOg8Pg-V194e_qei7CNgmIZ9xZlKY_txkmBbcG3oz9o-UhZGr4FZT6r6IUfTjkQCMROXf2hESLP8yF-kULRneIADtkw29s2i17iyBuG0cxEYHsQnJ2Y_aTL7MiZRDTYGEKQk4Uulz1WAuZ5yrSDJufcjZZpaBYqFUSWb5vSxtPLRsPk13IF5Xb48dtlaV1ruZAYZJubgiEzVQPEKXaL5e-SY_5wEHefLmPOHxvJT04UZlUnwp9C5sItjaZhN3gI6yiEQdqmdDv2_FOIKK8DTustT0rbAz4D_tAcy_p7709sTmdoCHMLePWBXcwh9TDnnQ.1J7vaomXiXYukQjmlQZ5PA.SlkSFKPGXBNTSmYm9QByRB31U1CVaWAQmqzSoNGBYuj5h7zNtpBnFrm3VstzdybVqJRLi4OzNWFIHusR3wmeFpcnEE9cJkFpWprbn0cskG7vVNfaKNMNKmTipfxUh83yXleuKVukJpAdP2WhYqxqMDYqz3Z1qQCODA1FALSMgL-O3heAxi4KJdbeLvU02iQ0fdM5pphdtF6pgCnDPyK0U_hEAPge8akLU_ELGxJPNkr8jiuJQ9gK5qhJVAb1riwVSxvte15mnSDfynI51MVAKQgMRJtUl61j93tIPawIM5g.YQUW54he59ty3AAmfG5VKQ"
}

2) Verify (decrypt and verify) an encrypted JWT

REQUEST -

curl -X POST -H "Content-Type: application/x-www-form-urlencoded" -d 'jwt=eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.RaFg8gIz4TdDM9IzJAWIGmOg8Pg-V194e_qei7CNgmIZ9xZlKY_txkmBbcG3oz9o-UhZGr4FZT6r6IUfTjkQCMROXf2hESLP8yF-kULRneIADtkw29s2i17iyBuG0cxEYHsQnJ2Y_aTL7MiZRDTYGEKQk4Uulz1WAuZ5yrSDJufcjZZpaBYqFUSWb5vSxtPLRsPk13IF5Xb48dtlaV1ruZAYZJubgiEzVQPEKXaL5e-SY_5wEHefLmPOHxvJT04UZlUnwp9C5sItjaZhN3gI6yiEQdqmdDv2_FOIKK8DTustT0rbAz4D_tAcy_p7709sTmdoCHMLePWBXcwh9TDnnQ.1J7vaomXiXYukQjmlQZ5PA.SlkSFKPGXBNTSmYm9QByRB31U1CVaWAQmqzSoNGBYuj5h7zNtpBnFrm3VstzdybVqJRLi4OzNWFIHusR3wmeFpcnEE9cJkFpWprbn0cskG7vVNfaKNMNKmTipfxUh83yXleuKVukJpAdP2WhYqxqMDYqz3Z1qQCODA1FALSMgL-O3heAxi4KJdbeLvU02iQ0fdM5pphdtF6pgCnDPyK0U_hEAPge8akLU_ELGxJPNkr8jiuJQ9gK5qhJVAb1riwVSxvte15mnSDfynI51MVAKQgMRJtUl61j93tIPawIM5g.YQUW54he59ty3AAmfG5VKQ' 'http://iloveapis2015-test.apigee.net/jwt_encrypted/validate?apikey=Xmzm0xlH27YerSdWzk78Gf3QHaP1WyQd'

RESPONSE

{
  "jwt": "eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.RaFg8gIz4TdDM9IzJAWIGmOg8Pg-V194e_qei7CNgmIZ9xZlKY_txkmBbcG3oz9o-UhZGr4FZT6r6IUfTjkQCMROXf2hESLP8yF-kULRneIADtkw29s2i17iyBuG0cxEYHsQnJ2Y_aTL7MiZRDTYGEKQk4Uulz1WAuZ5yrSDJufcjZZpaBYqFUSWb5vSxtPLRsPk13IF5Xb48dtlaV1ruZAYZJubgiEzVQPEKXaL5e-SY_5wEHefLmPOHxvJT04UZlUnwp9C5sItjaZhN3gI6yiEQdqmdDv2_FOIKK8DTustT0rbAz4D_tAcy_p7709sTmdoCHMLePWBXcwh9TDnnQ.1J7vaomXiXYukQjmlQZ5PA.SlkSFKPGXBNTSmYm9QByRB31U1CVaWAQmqzSoNGBYuj5h7zNtpBnFrm3VstzdybVqJRLi4OzNWFIHusR3wmeFpcnEE9cJkFpWprbn0cskG7vVNfaKNMNKmTipfxUh83yXleuKVukJpAdP2WhYqxqMDYqz3Z1qQCODA1FALSMgL-O3heAxi4KJdbeLvU02iQ0fdM5pphdtF6pgCnDPyK0U_hEAPge8akLU_ELGxJPNkr8jiuJQ9gK5qhJVAb1riwVSxvte15mnSDfynI51MVAKQgMRJtUl61j93tIPawIM5g.YQUW54he59ty3AAmfG5VKQ",
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

# Private Keys and Public Keys

1) The JWT is created by JWE standards using the public key to encrypt. 
2) Similarly at the time of verification the JWT is decrypted using the private key.
3) For this particular implementation it is assumed that that we will maintain the public key - private key pair per application(by API Key).

# Pre config step (mandatory) - 

Creating and managing Private Keys in Apigee Vault

Apigee Vault – A vault needs to be created per environment with the name “privateKeysByApp”. 

Further a Vault entry needs to be added to the above vault with name = client_id (apikey) and value = private key (base64 encoded).

The Apigee Vault API’s and documentation can be found here - http://apigee.com/docs/api-reference/api/vaults

In the runtime API call for verify encrypted JWT, we have a node.js target which grabs the private key by apikey form the vault.

# Build and Deploy - 

Since this is a node.js project you will either need apigeetool or maven to deploy this proxy.
This project is already set up with maven (parent and project pom.xml's).
All you need to do is to run the following maven command from the same folder that contains the pom.xml ie.. /jwt_encrypted/apiproxy.

mvn install -P {apigee_environment} -Dusername={YOUR_EDGE_USER_NAME} -Dpassword={YOUR_EDGE_PASSWORD} -Dorg={} -DskipTests=true -Dapigee.options=validate,update



