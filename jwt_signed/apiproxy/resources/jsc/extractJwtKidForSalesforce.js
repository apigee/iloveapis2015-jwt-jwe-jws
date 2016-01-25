// extractJwtKidForSalesforce.js
// ------------------------------------------------------------------

var jwt = context.getVariable(properties.jwtvar);

jwt = jwtDecode(jwt);

// set the RSA public key {m,e} for the particular Key-id into context variables
var modulus_b64 = context.getVariable('sfkey.' + jwt.header.kid + ".modulus");
var exponent_b64 = context.getVariable('sfkey.' + jwt.header.kid + ".exponent");

context.setVariable('sf_key_modulus', modulus_b64);
context.setVariable('sf_key_exponent', exponent_b64);
