var apigee = require('apigee-access');
var envVault = apigee.getVault('privateKeysByApp', 'environment');
var http = require('http');
var svr = http.createServer(function(req, resp) {

      var clientId = apigee.getVariable(req, 'client_id');
      envVault.get(clientId, function(e, privateKeyFromVault) {

        //console.log(privateKeyFromVault + " this value");
        //apigee.setVariable(req,"privateKeyFromVault",privateKeyFromVault);

        // var encodedKey = new Buffer(privateKeyFromVault, 'base64');
        // var decodedKey = encodedKey.toString();
        //apigee.setVariable(req,"privateKeyFromVault",decodedKey);
        //console.log(privateKeyFromVault + ":BASE64");

        // no decoding necessary
        envVault.get(clientId + "-password", function(e, privateKeyPassword) {
          apigee.setVariable(req,"privateKeyPemEncoded",privateKeyFromVault);
          apigee.setVariable(req,"privateKeyPassword", privateKeyPassword);

          resp.writeHead(200, { 'Content-Type': 'text/plain' });
          resp.end('Hello, World!\n');
        });
      });
    });


svr.listen(9000, function() {
  console.log('The server is listening on port 9000');
});
