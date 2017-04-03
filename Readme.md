# iloveapis2015-jwt-jwe-jws

This is the top-level project containing source code, documentation, and tools for the Devevloper Forum session entitied "ADVANCED SECURITY EXTENSIONS IN APIGEE EDGE: JWT, JWE, JWS"
 at the 2015 I-love-APIs conference in San Jose, California, 2015 October 12-14.  We also repeated this content in a recorded webcast on 2016 February 4. 

The example proxies included here will work on the Apigee Edge public cloud release, or on OPDK 16.01 or later. These proxies will not work on OPDK 15.07 or earlier.  This restriction does not apply to the Java callouts.  The custom Java policy work on OPDK 15.07 or on the Apigee public cloud. 


## What's going on here?

You will find subdirectories here, containing independent projects:

- [JWT (signed)](jwt_signed) - verifying Signed JWT in Edge
- [JWT (encrypted)](jwt_encrypted) - verifying Signed+Encrypted JWT in Edge
- [JWE](jwe) - producing and decrypting JWE in Edge


Each directory includes the Java source code for a callout, as well as an example API proxy, which shows how to use the callout. 


## Support

This is an open-source project of the Apigee Corporation. It is not covered by Apigee support contracts. However, we will support you as best we can. For help, please open an issue in this GitHub project, or ask on [community](https://community.apigee.com). You are also always welcome to submit a pull request.

## License

This material is Copyright 2015, 2016 Apigee Corporation, and Copyright 2017 Google Inc.  
It is licensed under the Apache 2.0 license. See the [LICENSE](LICENSE) file. 

## About Building

It is not necessary to build the Java source code contained in the subdirectories here, in order to use the JWT or JWE policies in Apigee Edge.  


## Pre-build step

If you do wish to build the callouts from Java source, you need [Apache maven](https://maven.apache.org/).  To allow the maven builds to succeed, you need to first run the buildsetup.sh script on your workstation. This adds the Apigee-required jars into the local maven repository (your local cache). 

Do this like so: 

```
  ./buildsetup.sh
```

You must have previously installed maven in order for the above step to succeed.

After the buildsetup, to build the jars with maven, follow the usual
steps.  This is described in greater detail in the Readme's in the callout source
directory for each sudirectory here.


# Sample Request calls 

If you have the [Postman tool](https://www.getpostman.com/) you can use [the collection](Advanced-Security-JWT-JWE-JWS.json.postman_collection) included in this repo. 
Otherwise for each use case, the sample requests have been well documented in the Readme's.
