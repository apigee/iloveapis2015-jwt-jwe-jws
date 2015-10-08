// extractJwtKidForGoogle.js
// ------------------------------------------------------------------

var jwt = context.getVariable(properties.jwtvar);

jwt = jwtDecode(jwt);

// set the certificate for the particular Key-id into a context variable
var cert = context.getVariable('googcert.' + jwt.header.kid);
context.setVariable('goog_certificate', cert);
