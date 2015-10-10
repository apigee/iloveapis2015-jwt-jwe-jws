JWE - encrypting anything
================

This api proxy creates JWE and decrypts JWE, aka JSON Web Encryption.  
JWE is an IETF standard.
https://tools.ietf.org/html/rfc7516

In short, JWE is just a way to wrap an encryption envelope around *anything*. 

Apigee Edge doesn't currently contain "native" capability to create or
decrypt JWE.  This proxy shows how to use a Java callout to do those
things.


Example Invocations:
----------------

**Encrypting data***

```
$ curl -i -X POST -d 'key=secret&plaintext=The quick brown fox....' \
     http://iloveapis2015-test.apigee.net/jwe/create-hs256
```

The response is like so: 

```
HTTP/1.1 200 OK
Host: iloveapis2015-test.apigee.net
Content-Length: 277
Content-Type: application/json
Connection: keep-alive

{
  "jwe" : "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiYWxnIjoiUEJFUzItSFMyNTYrQTEyOEtXIiwicDJjIjo4MTkyLCJwMnMiOiJCWHc5VWxJMl9uX2RXbGs2In0.Wev8woElErCQuV7qMzDGYXzEvuuQJ3Uo6TCk-PE8d6CnLlvnhkfeLQ.im-SuHPOZJUWMF80kGz3GQ.oe3le61B_liL1osmJUb1F3RxkzwMVIkHzSxYktO17zU.UcRea2B144efY1IBKCMHbw"
}
```


**Decrypting JWE**
```
$ curl -i -X POST -d 'key=secret&jwe=eyJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiYWxnIjoiUEJFUzItSFMyNTYrQTEyOEtXIiwicDJjIjo4MTkyLCJwMnMiOiJCWHc5VWxJMl9uX2RXbGs2In0.Wev8woElErCQuV7qMzDGYXzEvuuQJ3Uo6TCk-PE8d6CnLlvnhkfeLQ.im-SuHPOZJUWMF80kGz3GQ.oe3le61B_liL1osmJUb1F3RxkzwMVIkHzSxYktO17zU.UcRea2B144efY1IBKCMHbw'  http://iloveapis2015-test.apigee.net/jwe/decrypt-hs256 
```

The response is:

```
HTTP/1.1 200 OK
Host: iloveapis2015-test.apigee.net
Content-Length: 46
Content-Type: application/json
Connection: keep-alive

{
  "plaintext" : "The quick brown fox...."
}
```

