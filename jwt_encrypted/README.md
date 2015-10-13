JWT- encryped test proxy
================

This api proxy creates and validates encrypted JWT, aka JSON Web Tokens.  
JWT is an IETF standard.
https://tools.ietf.org/html/rfc7519

In short, JWT are just a special kind of OAuth v2 token.  The Oauth v2 spec...
https://tools.ietf.org/html/rfc6749#section-1.4

...says that Bearer tokens are strings that:

- are usually opaque to the client. 
- may denote an identifier used to retrieve the authorization
  information or may self-contain the authorization information in a
  verifiable manner

JWT are simply a form of the latter - authorization information
contained in a verifiable string. It can be either a signed string, or an encrypted string, that contains a
set of claims. Something like a SAML Token, but in JSON format.

Apigee Edge doesn't currently contain "native" capability to create or
verify JWT.  This proxy shows how to use a Java callout to do those
things.

# JWT (Encrypted)

This directory contains Java source code for a callout which verifies and creates encrypted JWT, 
as well as an example API proxy, which shows how to use the callout. 


- (callout) - Java code, as well as instructions for how to build the Java code.
- (apiproxy) - an example API Proxy for Apigee Edge that shows how to use the resulting Java callout


The API Proxy subdirectory here includes the pre-built JAR file. Therefore you do not need to build the Java code in order to use this JWT verifier. However, you may wish to modify this code for your own purposes. In that case, you will modify the Java code, re-build, then copy that JAR into the appropriate apiproxy/resources/java directory for the API Proxy.  


....

