# JWT (signed)

This directory contains Java source code for a callout which verifies signed JWT, 
as well as an example API proxy, which shows how to use the callout. 

- [Java source](callout) - Java code, as well as instructions for how to build the Java code.
- [apiproxy](apiproxy) - an example API Proxy for Apigee Edge that shows how to use the resulting Java callout


The API Proxy subdirectory here includes the pre-built JAR file. Therefore you do not need to build the Java code in order to use this JWT verifier. However, you may wish to modify this code for your own purposes. In that case, you will modify the Java code, re-build, then copy that JAR into the appropriate apiproxy/resources/java directory for the API Proxy.

## SPECIAL NOTE

Due to some changes in the provisioning of Apigee Edge SaaS organizations, this callout may not successfully run in newly-provisioned organizations. There are new security restrictions for Java callouts that may prevent the JAR from running properly.
Native JWT support is on Apigee's product roadmap. This statement is not a commitment; product plans are subject to change without notice.


## Support

This is an open-source project of the Apigee Corporation. It is not covered by Apigee support contracts. However, we will support you as best we can. For help, please open an issue in this GitHub project, or ask on [community](https://community.apigee.com). You are also always welcome to submit a pull request.

## License

This project and all the code contained within is Copyright 2016-2017 Google Inc., and is licensed under the [Apache 2.0 Source license](../LICENSE).


