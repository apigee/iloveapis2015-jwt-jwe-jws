var javaCalloutError = context.getVariable("jwt_error");
if(javaCalloutError === null || javaCalloutError === "") {
  var claimsReceived = JSON.parse(context.getVariable("jwt_receivedClaims"));
  if (claimsReceived.iss) {
    var issuer = claimsReceived.iss;
    context.setVariable("jwtIssuer", issuer);
  }

  if(claimsReceived.exp) {
    var jwtExpiration = claimsReceived.exp;
    context.setVariable("jwtExpiration", jwtExpiration);
    var systemTimeStamp = Math.floor(context.getVariable("system.timestamp")/1000);
    var tokenExpiresIn = ((Number(jwtExpiration) - Number(systemTimeStamp)) * 1000);
    context.setVariable("jwtExpiresIn", tokenExpiresIn.toString());
    context.setVariable("jwtIsExpired", tokenExpiresIn < 0);
  }

  if(claimsReceived.dealerId) {
    var dealerId = claimsReceived.dealerId;
    context.setVariable("dealerId", dealerId);
  }

  if(claimsReceived.active) {
    var active = claimsReceived.active;
    context.setVariable("active", active);
  }

  if(claimsReceived.jti) {
    var jti = claimsReceived.jti;
    context.setVariable("jti", jti);
  }
}
