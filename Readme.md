# iloveapis2015-jwt-jwe-jws

This is the top-level project containing source code, documentation, and tools for the Devevloper Forum session entitied "ADVANCED SECURITY EXTENSIONS IN APIGEE EDGE: JWT, JWE, JWS"
 at the 2015 I-love-APIs conference in San Jose, California, from 12-14 October.


## What's going on here?

You will find subdirectories here, containing independent projects:

- [JWT (signed)](jwt_signed) - verifying Signed JWT in Edge
- [JWT (encrypted)](jwt_encrypted) - verifying Encrypted JWT in Edge
- [JWE](jwe) - producing and decrypting JWE in Edge


Each directory includes the Java source code for a callout, as well as an example API proxy, which shows how to use the callout. 


## Pre-build step

It is not necessary to build the Java source code contained in the subdirectories here, in order to use the JWT or JWE policies in Apigee Edge.  But, if you do wish to build, to allow the maven builds to succeed, you need to first run the buildsetup.sh script on your workstation. This adds the Apigee-required jars into the local maven repository (your local cache). 

Do this like so: 

```
  ./buildsetup.sh
```

You must have maven installed in order for the above step to succeed.

After the buildsetup, to build the jars with maven, follow the usual
steps.  This is described in greater detail in the callout source
directory for each sudirectory here.

# Sample Request calls for all the use cases
If you have postman you can download the collection form this link - https://www.getpostman.com/collections/24101901a9797c0921a4
Otherwise for each use cases the sample requests have been well documented.
