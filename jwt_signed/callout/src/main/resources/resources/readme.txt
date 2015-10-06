The password for the public-private-keypair1.pem is deecee123

The public-key.pem just contains the extracted public key in PKCS#8 format. 

It is a 2048 bit keypair generated via: 
  openssl genrsa -des3 -out private.pem 2048

The public key was extracted via: 
  openssl rsa -in private.pem -outform PEM -pubout -out public.pem


The openid-connect-example-public.pem is from 
http://openid.net/specs/openid-connect-core-1_0.html#ExampleRSAKey

Actually - not exactly.  That example key is in JWK format. 
The one here has been converted from that format to PEM PKCS#8 Format. 

See also:
https://www.npmjs.com/package/pem-jwk
http://stackoverflow.com/a/27930720/48082

