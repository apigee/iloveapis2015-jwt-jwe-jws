// removeDeclaration.js
// ------------------------------------------------------------------
//
// Hack to remove the XML Decl in the response message.
// It's possible this could be done more simply by just doing this:
//
// response.content = response.content.asXML + '';
//

var s = context.getVariable(properties.xmldoc),
    L = s.length,
    ix1 = s.indexOf('<?'),
    ix2;

if (ix1 > 0) {
  ix2 = s.indexOf('>');
  if (ix2 > ix1) {
    s = s.substring(ix2 + 1);
    context.setVariable(properties.xmldoc, s);
  }
}
