var encodedPrivateKey = context.getVariable("privateKeyFromVault");


var javaCalloutError = context.getVariable("jwt_JavaCallout-JWE-Validate_error");
if(javaCalloutError === null || javaCalloutError === "")
{
	var claimsReceived = JSON.parse(context.getVariable("jwt_JavaCallout-JWE-Validate_receivedClaimsJSON"));
	if(claimsReceived.iss)
	{
		var issuer = claimsReceived.iss;
        context.setVariable("issuer", issuer);
	}
	if(claimsReceived.exp)
	{
        var jwtExpiration = claimsReceived.exp;
        context.setVariable("jwtExpiration", jwtExpiration);

        var systemTimeStamp = Math.floor(context.getVariable("system.timestamp")/1000);
        var accessTokenExpiration = "";
        accessTokenExpiration = ((Number(jwtExpiration) - Number(systemTimeStamp)) * 1000);
        accessTokenExpiration = accessTokenExpiration.toString();
        context.setVariable("accessTokenExpiration",accessTokenExpiration);

	}
	if(claimsReceived.dealerId)
	{
        var dealerId = claimsReceived.dealerId;
        context.setVariable("dealerId", dealerId);
	}
	if(claimsReceived.active)
	{
        var active = claimsReceived.active;
        context.setVariable("active", active);
	}
	if(claimsReceived.jti)
	{
        var jti = claimsReceived.jti;
        context.setVariable("jti", jti);
	}

}

else{
	context.setVariable("javaCalloutError",javaCalloutError);
}