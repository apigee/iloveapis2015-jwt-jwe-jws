# I love APIs 2015 - Advanced Security Extensions - JWT, JWE, JWS

This repo contains all the source code, sample api proxies, readmes, and other supporting information for the session entitled "Advanced Security Extensions - JWT, JWE, JWS" at Apigee's ILoveAPIS 2015 conference, held in San Jose California, 2015 October 12-14. 



## What's going on here?

This repo contains Java source code for Apigee Edge callout classes, that do JWT, JWE, and JWS.  You can build the Java callout classes and immediately begin using them in your API Proxies. 


## Pre-build step

To allow the maven builds to succeed, you need to run the buildsetup.sh script on your workstation. This adds the Apigee-required jars into the local maven repository (your local cache). 

Do this like so: 

 ```./buildsetup.sh```



