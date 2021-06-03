package com.google.apigee.callout.jwtsigned;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

public class HTTPUtil {

  public static String getResponsePayload(HttpURLConnection conn) throws Exception {

    String content = "";
    try (BufferedReader rd =
        new BufferedReader(
            new InputStreamReader(
                (conn.getResponseCode() >= 400) ? conn.getErrorStream() : conn.getInputStream()))) {
      for (String line = rd.readLine(); line != null; line = rd.readLine()) {
        content += line;
      }
    }
    return content;
  }

  public static Map<String, Object> post(
      String urlToPost, Map<String, String> formdata, Map<String, String> headers)
      throws Exception {
    HashMap<String, Object> result = new HashMap<String, Object>();

    URL siteUrl = new URL(urlToPost);

    HttpURLConnection conn = (HttpURLConnection) siteUrl.openConnection();
    conn.setRequestMethod("POST");

    String content = "";
    if (formdata != null) {
      content =
          formdata.keySet().stream()
              .map(
                  key -> {
                    try {
                      return key + "=" + URLEncoder.encode(formdata.get(key), "UTF-8");
                    } catch (UnsupportedEncodingException e) {
                      throw new RuntimeException(e);
                    }
                  })
              .collect(Collectors.joining("&"));
    }

    conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
    conn.setRequestProperty("Content-Length", "" + Integer.toString(content.getBytes().length));
    conn.setRequestProperty("Accept", "*/*");
    conn.setRequestProperty("Accept-Charset", "UTF-8");

    if (headers != null) {
      for (String key : headers.keySet()) {
        conn.setRequestProperty(key, headers.get(key));
      }
    }

    conn.setInstanceFollowRedirects(false);
    conn.setDoOutput(true);
    conn.setDoInput(true);
    conn.connect();

    try (DataOutputStream out = new DataOutputStream(conn.getOutputStream())) {
      out.writeBytes(content);
    }

    int code = conn.getResponseCode();
    result.put("code", new Integer(code));
    result.put("headers", conn.getHeaderFields()); // Map<String, List<String>>
    result.put("content", getResponsePayload(conn));
    conn.disconnect();
    return result;
  }

  Map<String, Object> get(String urlToRead) throws Exception {
    HashMap<String, Object> result = new HashMap<String, Object>();
    URL url = new URL(urlToRead);
    HttpURLConnection conn = (HttpURLConnection) url.openConnection();
    conn.setInstanceFollowRedirects(false);
    conn.setRequestMethod("GET");
    conn.setRequestProperty("Accept-Charset", "UTF-8");
    conn.connect();

    int code = conn.getResponseCode();
    result.put("code", new Integer(code));
    result.put("headers", conn.getHeaderFields()); // Map<String, List<String>>
    result.put("content", getResponsePayload(conn)); // String
    conn.disconnect();
    return result;
  }

}
