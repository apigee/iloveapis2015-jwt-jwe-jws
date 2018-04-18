// setPrivateKeyVariables.js
// ------------------------------------------------------------------
//
// created: Wed Apr 18 12:33:18 2018
// last saved: <2018-April-18 13:51:28>

'use strict';

var privateVariablesToSet = {
      "privateKeyPem_passphrase" : "Apigee-IloveAPIs",
      "privateKeyPem" : "-----BEGIN RSA PRIVATE KEY-----\n" +
    "Proc-Type: 4,ENCRYPTED\n" +
    "DEK-Info: DES-EDE3-CBC,171EA6A387A34BF7\n" +
    "\n" +
    "eoZdqVDEdtqvtlWWCYYNy3gGnK3bs5/y7nqw97Jf1NF0E2m8UzpinkR0w0HL5c7p\n" +
    "NvzJzHGtlntD9qd7E6hIdUsy96884rLXHmdehGDnPfPl223ofo6qq36pcaVyw6Nu\n" +
    "ImhLij4DtVoUTtiRqnhSje1MbM9nBOOGdNbgzi1QF7xvwoVq18g4QjyHF7SxV0hr\n" +
    "VLRjnIDqVig+HJgvp27nRc6mV+W4gVLKnuJaeBJpAW9harMzDA/kk8F0rbhHyLhJ\n" +
    "qfV9qx2uacXly8LgkVI/3wNgohelJ+YxSw+z27NzovgjJnhEnwXG5ZTZ502Ow/F8\n" +
    "GKsSPVw8g3UixI2g8L69nt1jAaE5sFCpzJkL1RO5+tqZ598SKOjnZpRqbMm+iPjm\n" +
    "DLjeSU1PKKeDx9E8J8QD1YFFJDlLQP2Lbsq8tx8xNwPOAwEixZqumftwoSFe2R0z\n" +
    "PtvlMpPvX08SvXz/OaysA3a+/sq6IizSZoKgq6S6dTrLx3GEPI4f1tWvirVbD87B\n" +
    "ImWNynNP2k6uG+Y1rpcdirKItp4iwLckMACuOAF5efB4rxDtce/h5dlqWY+JQ/UQ\n" +
    "IPsCxJjP4SiK+u4YZENhS9wZUhA1GRTFP84Q36tuTIb3Bdv5u01P6HxycbFyF0NU\n" +
    "Fx40Y4zcMMjGav8TR9vPlqgLqTYIpjPeydPqYZob5llBRMdCKVRtZfWSVKgjtemj\n" +
    "UjudYfgMovyvpzLiNVwFTUtuHQyqeZ92lQ9k5uRSMWhGKJxrEcYMl/laGiXIguwy\n" +
    "u/FSmzUco0wTSOKjJTXVHPD0fZYctd7l114uqGH0zO6SZjIiBWiDOW/q7Onpn4A+\n" +
    "Elt1u/bVb8wZBr8chFGaMUfd6TW2LieOa23W2X1KxXZhynT2s7PZn3IIu2TJtM8r\n" +
    "3ylQvZaHZRoDjexCZY7Ry1/J60hxDkSP1KZLpEekYwYTfJPHh0OWaHtWTAkOqOT9\n" +
    "4WFAAnUqXpH+HOsiht7IFibepIghnMg6FOTZVgIgP5lAdHGDjbzCS7VuvGYQ/O6b\n" +
    "exVCmUB4MV6qcHtiwsDV6QWukBRfdY8OZniMaSVpV/X14QKj3PmXIpxyrGXKOK4m\n" +
    "OZedGRkLaTz9quF0+Vf1JSog6upw4qLpnge0HJz5x1XMcnpvlw0PjXnrNIo/Rj7O\n" +
    "WMsfFACnvaQyJXTk3Ul/MKUhuwRGtgD3htAIqpX91hMf+89JeE4ThaAcLfL2Mbit\n" +
    "sU3JLxEmNTIz6+GjQgeU/fZU2xg8gBnyCIh2CfpyhiyjfyWol+76TBqgFpz+QNGf\n" +
    "UYB9J4xbsVDc8XFhUBd0mY1pWASqREuU+qeDbx8DSqvun7YbP4Px5HzK+h+o1gV6\n" +
    "Ge4GFh3FIpwwKdZRxTpvKkE/0A3O1HOAUppvrERjWhdZcpDCRYP7R90k+B3FIVCT\n" +
    "ddUnryiJ/SmEEApn5swcJueLZgkBJluW1dg2RHYQcKu64wrKq66PmwaVOFo/T7bD\n" +
    "O8OPnhSgbxM+UdZPwmr7aKeoLPg9YvT2PJbKumQ68BDgrTWav/eUAElY3bNL+pf7\n" +
    "W6dD5I+Izacqn03jJgbDnIpdtFW3zsC1MYesfavVtRmdKlyV1fZBPDl5+F/kSCv1\n" +
    "-----END RSA PRIVATE KEY-----\n"
    };

var otherVariablesToSet = {
      "user_attrs" : JSON.stringify({alpha: 1, beta: true, gamma: "sometimes", epsilon: [14, 88, null]})
    };

function setVariables(prefix, variables) {
  prefix = (prefix) ? (prefix + '.') : '';
  for (var prop in variables) {
    context.setVariable(prefix + prop, variables[prop]);
  }
}

setVariables('should_be_private', privateVariablesToSet);
setVariables(null, otherVariablesToSet);
