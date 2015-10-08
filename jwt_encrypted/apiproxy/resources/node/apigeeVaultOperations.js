var http = require('http');
var apigee = require('apigee-access');
var svr = http.createServer(function(req, resp) {

var clientId = apigee.getVariable(req, 'client_id');
var envVault = apigee.getVault('privateKeysByApp', 'environment');
envVault.get(clientId, function(err, privateKeyFromVault) {

//console.log(privateKeyFromVault + " this value");
//apigee.setVariable(req,"privateKeyFromVault",privateKeyFromVault);


var encodedKey = new Buffer(privateKeyFromVault, 'base64');
var decodedKey = encodedKey.toString();
apigee.setVariable(req,"privateKeyFromVault",decodedKey);
console.log(privateKeyFromVault + ":BASE64");


resp.writeHead(200, { 'Content-Type': 'text/plain' });
resp.end('Hello, World!\n');
});


});


svr.listen(9000, function() {
  console.log('The server is listening on port 9000');
});