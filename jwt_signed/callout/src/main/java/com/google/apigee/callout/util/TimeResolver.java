package com.google.apigee.util;


import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class TimeResolver {
    private static final Pattern expiryPattern =
        Pattern.compile("^([1-9][0-9]*)(s|m|h|d|w|)$", Pattern.CASE_INSENSITIVE);
    private static final Map<String, Long> timeMultipliers;
    private static String defaultUnit = "s";

    static {
      Map<String, Long> m1 = new HashMap<String, Long>();
      m1.put("s", 1L * 1000);
      m1.put("m", 60L * 1000);
      m1.put("h", 60L * 60 * 1000);
      m1.put("d", 60L * 60 * 24 * 1000);
      m1.put("w", 60L * 60 * 24 * 7 * 1000);
      timeMultipliers = Collections.unmodifiableMap(m1);
    }

    public static ZonedDateTime getExpiryDate(String expiresInString) {
      Long milliseconds = resolveExpression(expiresInString);
      Long seconds = milliseconds / 1000;
      int secondsToAdd = seconds.intValue();
      if (secondsToAdd <= 0) return null; /* no expiry */
      ZonedDateTime zdt = ZonedDateTime.now(ZoneOffset.UTC);
      zdt = zdt.plusSeconds(secondsToAdd);
      return zdt;
    }

    /*
     * Convert a simple time duration string, expressed in days, hours, minutes,
     * or seconds, in a form like 30d, 12d, 8h, 24h, 45m, 30s, into a numeric
     * quantity in milliseconds.  Eg, "10s" is converted to 10000.
     *
     * Default TimeUnit is s. Eg. the string "30" is treated as 30s.
     */
    public static Long resolveExpression(String subject) {
      Matcher m = expiryPattern.matcher(subject);
      if (m.find()) {
        String key = m.group(2);
        if (key.equals("")) key = defaultUnit;
        return Long.parseLong(m.group(1), 10) * timeMultipliers.get(key);
      }
      return -1L;
    }
  }
