// Copyright 2018-2020 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package com.google.apigee.callout.jwtsigned;

import com.apigee.flow.message.MessageContext;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public abstract class JoseCalloutBase {
  private String varNamePrefix;
  protected Map<String, String> properties;
  private static final Pattern variableReferencePattern;
  private static final Pattern commonErrorPattern;

  static {
    java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    variableReferencePattern = Pattern.compile("(.*?)\\{([^\\{\\} \"]+?)\\}(.*?)");
    commonErrorPattern = Pattern.compile("^(.+)[:;] (.+)$");
  }

  protected JoseCalloutBase(String varNamePrefix, Map properties) {
    this.varNamePrefix = varNamePrefix;
    // convert the untyped Map to a generic map
    Map<String, String> m = new HashMap<String, String>();
    Iterator iterator = properties.keySet().iterator();
    while (iterator.hasNext()) {
      Object key = iterator.next();
      Object value = properties.get(key);
      if ((key instanceof String) && (value instanceof String)) {
        m.put((String) key, (String) value);
      }
    }
    this.properties = Collections.unmodifiableMap(properties);
  }

  protected String varName(String s) {
    return varNamePrefix + s;
  }

  protected boolean getDebug() {
    String value = (String) this.properties.get("debug");
    if (value == null) return false;
    if (value.trim().toLowerCase().equals("true")) return true;
    return false;
  }

  static InputStream getResourceAsStream(String resourceName) throws IOException {
    // forcibly prepend a slash
    if (!resourceName.startsWith("/")) {
      resourceName = "/" + resourceName;
    }
    InputStream in = JwtCreatorCallout.class.getResourceAsStream(resourceName);
    if (in == null) {
      throw new IOException("resource \"" + resourceName + "\" not found");
    }
    return in;
  }

  protected String getSecretKey(MessageContext msgCtxt) throws Exception {
    String key = (String) this.properties.get("secret-key");
    if (key == null || key.trim().equals("")) {
      throw new IllegalStateException("secret-key is not specified or is empty.");
    }
    key = (String) resolvePropertyValue(key, msgCtxt);
    if (key == null || key.trim().equals("")) {
      throw new IllegalStateException("secret-key is null or empty.");
    }
    return key;
  }

  protected String getAlgorithm(MessageContext msgCtxt) throws IllegalStateException {
    String algorithm = ((String) this.properties.get("algorithm")).trim();
    if (algorithm == null || algorithm.trim().equals("")) {
      throw new IllegalStateException("algorithm is not specified or is empty.");
    }
    algorithm = resolvePropertyValue(algorithm, msgCtxt);
    if (algorithm == null || algorithm.trim().equals("")) {
      throw new IllegalStateException("issuer is not specified or is empty.");
    }
    if (!(algorithm.equals("HS256") || algorithm.equals("RS256"))) {
      throw new IllegalStateException("unsupported algorithm: '" + algorithm + "'");
    }
    return algorithm;
  }

  protected String resolvePropertyValue(String spec, MessageContext msgCtxt) {
    Matcher matcher = variableReferencePattern.matcher(spec);
    StringBuffer sb = new StringBuffer();
    while (matcher.find()) {
      matcher.appendReplacement(sb, "");
      sb.append(matcher.group(1));
      Object v = msgCtxt.getVariable(matcher.group(2));
      if (v != null) {
        Class clz = v.getClass();
        if (clz.isArray()) {
          sb.append(Arrays.stream((Object[]) v).map(Object::toString).toArray(String[]::new));
        } else {
          sb.append(v.toString());
        }
      }
      sb.append(matcher.group(3));
    }
    matcher.appendTail(sb);
    return sb.toString();
  }

  // If the value of a property value contains open and close curlies, eg,
  // {apiproxy.name} or ABC-{apikey}, then "resolve" the value by de-referencing
  // the context variables whose names appear between curlies.
  //
  // This can return a String or an String[].
  //

  // If the value of a property contains any pairs of curlies,
  // eg, {apiproxy.name}, then "resolve" the value by de-referencing
  // the context variables whose names appear between curlies.
  protected Object resolvePropertyValueToObject(String spec, MessageContext msgCtxt) {
    int open = spec.indexOf('{'), close = spec.indexOf('}'), L = spec.length();
    if (open == 0 && close == L - 1) {
      // if there is a single set of braces around the entire property, and there are no
      // intervening spaces or double-quotes,
      // the value may resolve to a non-string, for example an array of strings.
      String v = spec.substring(1, L - 1);
      if ((v.indexOf('{') == -1)
          && (v.indexOf('[') == -1)
          && (v.indexOf(' ') == -1)
          && (v.indexOf('"') == -1)) {
        return msgCtxt.getVariable(v);
      }
    }

    return resolvePropertyValue(spec, msgCtxt);
  }

  protected static String getStackTraceAsString(Throwable t) {
    StringWriter sw = new StringWriter();
    PrintWriter pw = new PrintWriter(sw);
    t.printStackTrace(pw);
    return sw.toString();
  }

  protected void setExceptionVariables(Exception exc1, MessageContext msgCtxt) {
    // if (getDebug()) {
    //   exc1.printStackTrace(System.out); /* to MP system.log */
    // }
    String error = exc1.toString().replaceAll("\n", " ");
    msgCtxt.setVariable(varName("exception"), error);
    Matcher matcher = commonErrorPattern.matcher(error);
    if (matcher.matches()) {
      msgCtxt.setVariable(varName("error"), matcher.group(2));
      msgCtxt.setVariable(varName("reason"), matcher.group(2));
    } else {
      msgCtxt.setVariable(varName("error"), error);
    }
  }
}
