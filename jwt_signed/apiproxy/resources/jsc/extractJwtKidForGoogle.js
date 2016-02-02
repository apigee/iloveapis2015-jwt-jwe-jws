// extractJwtKidForGoogle.js
// ------------------------------------------------------------------

var jwt = context.getVariable(properties.jwtvar);
if (jwt && jwt.length > 0) {
  try {
    jwt = jwtDecode(jwt);
    // set the certificate for the particular Key-id into a context variable
    var cert = context.getVariable('googcert.' + jwt.header.kid);
    context.setVariable('goog_certificate', cert);
  }
  catch (exc1) {
    context.setVariable('goog_certificate', null);
  }
}
