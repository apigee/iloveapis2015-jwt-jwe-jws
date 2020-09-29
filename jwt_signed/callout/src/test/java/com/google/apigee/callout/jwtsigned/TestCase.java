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

import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.HashMap;

public class TestCase {
  private static final ObjectMapper om = new ObjectMapper();

  private String _testName;
  private String _description;
  private HashMap<String, String> _properties;
  private HashMap<String, String> _expected;

  // getters
  public String getTestName() {
    return _testName;
  }

  public String getDescription() {
    return _description;
  }

  public HashMap<String, String> getInputProperties() {
    return _properties;
  }

  public HashMap<String, String> getExpected() {
    return _expected;
  }

  // setters
  public void setTestName(String n) {
    _testName = n;
  }

  public void setDescription(String d) {
    _description = d;
  }

  public void setInputProperties(HashMap<String, String> m) {
    _properties = m;
  }

  public void setExpected(HashMap<String, String> e) {
    _expected = e;
  }

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
