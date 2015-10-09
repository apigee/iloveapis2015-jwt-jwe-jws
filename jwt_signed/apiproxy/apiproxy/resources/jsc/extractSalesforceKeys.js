// extractSalesforceKeys.js
// ------------------------------------------------------------------

var r = JSON.parse(context.getVariable('sfKeys.content'));

if (r.keys) {
  // an array of elements, like this:
  // {
  //   "use": "sig",
  //   "e": "AQAB",
  //   "kty": "RSA",
  //   "alg": "RS256",
  //   "n": "sTuRuR0_k....i3H8P-4A0",
  //   "kid": "198"
  // },

  // set context variables containing the n string for each SF Key
  r.keys.forEach(function (item) {
    if (item.kty == "RSA") {
      context.setVariable('sfkey.' + item.kid + ".modulus", item.n);
      context.setVariable('sfkey.' + item.kid + ".exponent", item.e);
    }
  });

}
