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

....