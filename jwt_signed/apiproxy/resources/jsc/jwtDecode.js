// jwtDecode.js
// ------------------------------------------------------------------
//
// Description goes here....
//
// created: Thu Oct  8 10:57:40 2015
// last saved: <2015-October-08 11:20:16>


function base64Decode(input) {
  // Takes a base 64 encoded string "input", strips any "=" or
  // "==" padding off it and converts its base 64 numerals into
  // regular integers (using a string as a lookup table). These
  // are then written out as 6-bit binary numbers and concatenated
  // together. The result is split into 8-bit sequences and these
  // are converted to string characters, which are concatenated
  // and output.

  // The index/character relationship in the following string acts
  // as a lookup table to convert from base 64 numerals to
  // Javascript integers
  var swaps = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
      ob = "",
      output = "",
      tb = "",
      i, L;

  input = input.replace("=",""); // strip padding

  for (i=0, L = input.length; i < L; i++) {
    tb = swaps.indexOf(input.charAt(i)).toString(2);
    while (tb.length < 6) {
      // Add significant zeroes
      tb = "0"+tb;
    }
    while (tb.length > 6) {
      // Remove significant bits
      tb = tb.substring(1);
    }
    ob += tb;
    while (ob.length >= 8) {
      output += String.fromCharCode(parseInt(ob.substring(0,8),2));
      ob = ob.substring(8);
    }
  }
  return output;
}

function jwtDecode(input){
  var parts = input.split('.'),
      header, payload;
  if (parts.length !== 3) {
    return null; // not a valid JWT
  }
  header = base64Decode(parts[0]);
  header = header.replace(/\0/g, '');
  header = JSON.parse(header);

  payload = base64Decode(parts[1]);
  payload = payload.replace(/\0/g, '');
  payload = JSON.parse(payload);

  return {
    header: header,
    payload : payload,
    sig : parts[2]
  };
}
