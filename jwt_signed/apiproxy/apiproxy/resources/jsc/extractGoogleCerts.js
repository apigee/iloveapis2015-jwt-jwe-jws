// extractGoogleCerts.js
// ------------------------------------------------------------------

var r = JSON.parse(context.getVariable('googCerts.content'));

// set context variables containing each PEM strings for each google certificate
Object.keys(r).forEach(function (key) {
  context.setVariable('googcert.' + key, r[key]);
});
