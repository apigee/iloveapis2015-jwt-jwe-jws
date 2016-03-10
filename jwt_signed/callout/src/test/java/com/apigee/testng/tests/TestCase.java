package com.apigee.testng.tests;

import java.util.HashMap;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonRawValue;
import com.fasterxml.jackson.databind.ObjectMapper;

public class TestCase {
    private final static ObjectMapper om = new ObjectMapper();

    private String _testName;
    private String _description;
    private HashMap<String,String> _properties;
    private HashMap<String,String> _expected;

    // getters
    public String getTestName() { return _testName; }
    public String getDescription() { return _description; }
    public HashMap<String,String> getInputProperties() { return _properties; }
    public HashMap<String,String> getExpected() { return _expected; }

    // setters
    public void setTestName(String n) { _testName = n; }
    public void setDescription(String d) { _description = d; }
    public void setInputProperties(HashMap<String,String> m) { _properties = m; }
    public void setExpected(HashMap<String,String>  e) { _expected = e; }

    // @JsonRawValue
    // public String getExpected() { return _stringOrMapValue(_expected); }
    //
    // private String _stringOrMapValue(Object o) {
    //     if (o == null) return null;
    //     if (o instanceof Map) {
    //         try {
    //             //return om.writerWithDefaultPrettyPrinter().writeValueAsString(o);
    //             return om.writeValueAsString(o);
    //         }
    //         catch (java.lang.Exception exc1) {
    //             return "error";
    //         }
    //     }
    //     // else, it has been deserialized as a String
    //     return o.toString();
    // }
}
