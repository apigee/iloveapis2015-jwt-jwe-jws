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

import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.message.MessageContext;
import java.util.HashMap;
import java.util.Map;
import mockit.Mock;
import mockit.MockUp;
import org.testng.annotations.BeforeMethod;

public abstract class JoseTestBase {

  protected MessageContext msgCtxt;
  protected ExecutionContext exeCtxt;

  protected static final Map<String, String> privateKeyMap;
  protected static final Map<String, String> publicKeyMap;
  protected static final String gettysburgAddress =
      "Four score and seven years ago our fathers brought forth on "
          + "this continent, a new nation, conceived in Liberty, and dedicated to the "
          + "proposition that all men are created equal.\n\n"
          + "Now we are engaged in a great civil war, testing whether that nation, or "
          + "any nation so conceived and so dedicated, can long endure. We are met on "
          + "a great battle-field of that war. We have come to dedicate a portion of "
          + "that field, as a final resting place for those who here gave their lives "
          + "that that nation might live. It is altogether fitting and proper that we "
          + "should do this.";


  static {
    // TODO - put this data in a resources directory in the filesystem
    Map<String, String> m = new HashMap<String, String>();
    m.put(
        "rsa-public-1",
        "-----BEGIN PUBLIC KEY-----\n"
            + "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyyTD+a4vyRx2Ng4LH/+D\n"
            + "di19c42W5dk/OVNor31IcEvN2H9GvTruOQZLJ29yka2SajiV3xJUjjxCTD9y9F14\n"
            + "Tj/E1z3JEa3rMIorh+EadABQn+qjkXjYAD8ASAjdZfaDSciS5D5cKgafxEV/0DwW\n"
            + "xlM1ZVmtEn6IdPNYpfuSuilhd1rP/VANiLMzmnrb6ZkNGdUzW6MYRz8tiA7VPkTH\n"
            + "DyN6+jclCucq5WTiC871PgA/nR81yY7FLiF0mElaveXf/PecSn5A3wOC/wKch55y\n"
            + "ATxhWpB0sA7tnIBDUX/XX4jn63RfmxmVTvol3QYMDGbyz4MB3LWTtojVK2QUaUib\n"
            + "qQIDAQAB\n"
            + "-----END PUBLIC KEY-----\n");

    m.put(
        "rsa-public-2",
        "-----BEGIN PUBLIC KEY-----\n"
            + "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA05nqYeFZzVrM/I4V/nJM\n"
            + "MZsQicVxxjgLoxp9eAiJcwl6TdTEngqIIskHhpHqpGwi/ohcv1nO/lPW738foE7b\n"
            + "mxV8h6BBynU5+q1SrFyXDvJSivFlEqvx0mnUPn+nTYxwMGKs0ZwXeAU2LdC8VLoP\n"
            + "SMwOxSe1NfR5KE9Elb+MMXmpzzWNXC9irkABAvZeQ4h9HGUcHVB+BnuhI8KX2HYw\n"
            + "9/Gj8M6j98nMOm9ILmOsyYLqvmXTbEj25EBfiXhW8WFHkzRjVNNImCGHMqblGpHg\n"
            + "QgHjY3O3ymeU2F2/bra6ophWedwHgbFe1gtiRBHRjLr0ntZYPx+qDxQyLLvQybGV\n"
            + "wQIDAQAB\n"
            + "-----END PUBLIC KEY-----\n");

    m.put(
        "rsa-public-3",
        "-----BEGIN PUBLIC KEY-----\n"
            + "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7Wb9p0wqUwq5ZIpUG0+MgKwidb0TXeEV\n"
            + "i86bhhoaHwzuwZPdrZLanBCQCxp2gzp5WxW3huO91P89fXaX4IPqLWZn/s9aLxJk+ZiMfSrc49mJ\n"
            + "H99pZ4/eHA9LyGNVvQ1Yj6WIrdQIMBypwyWTYqOBLsQp6Ouo7K0t5c0XhKJUDuebdRx9WM7PSXVX\n"
            + "r+u8BwL3+BW03lHp4tFgZhYae16mMV3DNlgHuBAusB6tQZT4yrn/lPhueTf2ie7pz2OVdjT9C5fZ\n"
            + "+vRA23tvanusyP5j9zMGKR5sMSnPijwOLiOBPuMWcsFiLeL+LY3uV0Ii5mtIbS78UUVmncrin/6u\n"
            + "9Es1AwIDAQAB\n"
            + "-----END PUBLIC KEY-----\n");
    publicKeyMap = java.util.Collections.unmodifiableMap(m);

    m = new HashMap<String, String>();
    m.put(
        "rsa-private-1", // password: deecee123
        "-----BEGIN RSA PRIVATE KEY-----\n"
            + "Proc-Type: 4,ENCRYPTED\n"
            + "DEK-Info: AES-256-CBC,4684005C83886CD7C0A942FD5A2D9340\n"
            + "\n"
            + "zroU3A5VxVdtq8FLY6wancxa8HUMjJp+HQwnFSu4x+1aAOor9ZHJcVotHUmRfhpy\n"
            + "MzdI2TsCCAo7Lw3yOCPXM4KhByky7ej1D63NOujMTdb2iClRXzinZj3RhwI1jNmK\n"
            + "rjJesTHR3Ed70+ucIAbQMPcr4Gn5hHunwDw7pYdMHzpoCy4t97oDZTufv51vQoyr\n"
            + "/4aoK5w+cg55oMWIbIB3pbyS4INpHcG3WrqJCL9U9Pv1ulWxlSkaQceAcsBz9T17\n"
            + "OODHQmkoNErTgiz0oKY3iWnKWj5Q2qYYjDSTFQFExcV9sFn5XCAI/s1nYpke3JQs\n"
            + "GOSlC6ly4YBDiKSj3D8w4mE1nvgIV4WQIGdE4Kvh/UApr1s09tY4FY4V3TRnO19D\n"
            + "kdBliqe6JRvmWlOfDI+yXYpzfUmBCAHuJWfIo75B95Uw3h4n9J4khgA2pBJVjwIe\n"
            + "OzPVJrEVx0SyqpJcPXCzmA4pkFJRyY/8MJV8R2d70rWvWmxDLExZ9HfXCN9DFrHI\n"
            + "PEpj39sTqdn1SaBCYqcArysW2qVC7pRrOloN2uwAKhy8EyMoyxXm+6BbhWx67Vcj\n"
            + "hlb7Db+8hFpqUGUZFV+TCrj0eRZotQrUqU1S544+k1cCm5gA1XLxUf/YXBvHgeMn\n"
            + "OfFz3W6lRbTyFq0QDsoHq8RFN4RVaQ9wz2n3H8oOxO5N7+HtkHf9fUby7Y48vaZT\n"
            + "UHMUgkgz9IbXVRyX83Q2+Yo4sMvDbAijDUwkyEhL/lg+mjoOo0zQ7dmCG49/mJXk\n"
            + "7TAXwPYMUfF4RuBy9fgU68uKsXCixVzpa8udvYul6mOhdaTm27BaCuZzJBKUGi2S\n"
            + "JvH0ZBH/+N9E+YajoPiJz00+IKGS5lfVH2QaRuw22QPMCUp/YWBqm9+rYgI40Skc\n"
            + "6iqNtlanoTttCcFtvzLt5RDjtqhP40k64yI64rcEaTKMC9zHXF3SJ9lCKsLqR6Jh\n"
            + "shOIeVdALu+HOMUeO1Vy6jQUbIauovQZoH8wkbLjdOaNLRaROWsz7TGm/9NsO2pd\n"
            + "zZ3s40Z/C475bZqeEkmZdf06LqGRSzNFwLTPgi2YX1HNs3l6bph95vlno7G/rOcT\n"
            + "IpVezK925rtAWEqaS88ubXoKWDxLRvBJBIc+17IOJZNifgLouyr7eC7A5TWUTwrb\n"
            + "QDwkAvRykBW39a+pqczTAQqw6mY0pm0lyZQj9sB5D2KvqFIiGAjUyZRwqY8E43+r\n"
            + "7XEVuE/Kc3oJ2JOeWEg5/REQumMMLGTm1ivsby9IXRgwrhqgzMk6hb9wuDnCXeE6\n"
            + "acf97ALJe0GK646rbHRLHauQtJ+gonenPg9UvK6rvE4hMBjsNzlI9OZaKCsXoxP+\n"
            + "AoErOJO2Vz7nXGlGKUMCySncjalTQl5ZD/Uf3FxrRP2aqzSvzEnuXvwCiPj0Rqrk\n"
            + "oMHyYNsLPdhIHJRDIlNQ/zfKEzzySB6otpheSYXkTu8W+LbwJXzgZUTmKHmbUmHA\n"
            + "Awwmw2yakRrjEkJDGgzSOZM951zcebHVJXq/VcLSejf/b0qqvDfETc9DIi64sexQ\n"
            + "M6ufhowuwrx1UZKOjWJ3A6sWuk1n0eMHZpgPpX37n6gmFREhIUBCqIXKSq2NVp21\n"
            + "-----END RSA PRIVATE KEY-----\n");

    m.put(
        "rsa-private-2", // password: Secret123
        "-----BEGIN RSA PRIVATE KEY-----\n"
            + "Proc-Type: 4,ENCRYPTED\n"
            + "DEK-Info: DES-EDE3-CBC,6DE5F5E50CD06DD7\n"
            + "\n"
            + "3FzVlbLmjRSJvRPCEy0uYlzbNveWOxwz8xfHPO+/iZcPfcIpFe/KLz1Fx5TjgJaW\n"
            + "OBanfj5/mwXAnO7ZTH7caw3Ymp5wpFsbcuTUwOXKUlRP10a6sFImIO8BJmfJE2ND\n"
            + "EsUyzsAzCh0kedjgU/SBlBbMPhgLMG7s0v1GiP+0y8AJVNhASVmvh2PFf6ttjk06\n"
            + "Gg2EXVKDDatM9RbFKdYUqwkeaSdb5xT9LlovF2NUXAjvRgxGUn+/ky60h7g1ljVL\n"
            + "LhdS9UQ9SmjIgy1QvuSjwlTD2CzZX2O1lFtAJ8Kkon8l7rwz1GH0aiAHJnavGvuP\n"
            + "gsO7srHLfjY961TY4vHWFefiBoRmviMYNlx8CaVqrceaj9Uf3xL+IFo3aRMbGBo4\n"
            + "qw+MqRS+wgu5KGWHjkqgagGXmMFA/P9wOgvAw7i211UtYJAPflntAjWmbHJpirSi\n"
            + "Pt/41V0YAdsbeMUhn/SXI4F2/tqrMUVH0XTuqXQK/dP/POMrOPVQNSZszpcfnsG+\n"
            + "tAeuUsnF5J1+spROo6juhnAUdPksFsrASiJ4mRlHkY+/UJ5RyIa8xrPIGvrBQ44b\n"
            + "XFYrWnjyPQ9Gbxqlo9xv9ZEbcxZMfEsbeMQ2DfQpcmIwSquQ7oV1odtNhXv0mWQY\n"
            + "T6z77kid2Gpo05ro2TSoRU8nUlObIwsysfNbMZH4GGxQYkhvkP33vdShIvZsYT5y\n"
            + "Btx4fxwPpEFJqMX/hX8Dxb7g7x9z8bmvU8S2va9LZ80ktWwsN09ViCy0XT/mLvxG\n"
            + "yzt2wJ6B1ksKqpwJHiEERmYTnTuJo9fNffbaQpqDFpuY8/hT+XhDM0yEuT14+kd/\n"
            + "MQ6mMY5d0GlM6u2dyuOBMgPOrcKH5jG7huqd59LvVfQKcq7kGvX2spU1Y3PfFYBr\n"
            + "smQdl50cxqAdPRYfw7qoD8cgMkVD9+B13a+EDSqLEV5E2gm+inmhKkZaobrA30D2\n"
            + "+2rvLZTFo+gJTQu4TGxu7WnZfv+t4fBBC/16+UPQR2A8zS+/31C9pND9Yx9DiH6n\n"
            + "JcQ8QyEPqOTOxHHxyR0Eo83tXAz46PDJmz4azOJODpO8OfEiRHJNRZGBgZmwxg3V\n"
            + "gxWdP+7UT2nkAb6dYvflXsXRT/BYlttCmk3a38hUw+tPFpdUQ/qGGVgoioMHoBF6\n"
            + "zQPgH5JEEYdVJglQnPlMZoL536qRFCUOv4Q/yj61C1uN/NM3Abxcg5rjaS1WAarq\n"
            + "V8YJDOowbJlnMmOZ4C0g96ZJZKWULJ17QwwGqEXJTEIYBJC8e7/yMd/0b3NMAZCP\n"
            + "PLhjeCpgD+jUJbyVkUrujobVFSdEjIaVN1fsCZUSFWWD9s2y/6WV9KY4Lm+2Eiau\n"
            + "WDtD25J3akm5/tklMbdkd0DoYw4zUM9cmkaSG71JZGG7owLt+Gmkfc3o5IwqzPx1\n"
            + "YwRf4bER9T5ETrnPS6Q6f5mxRXgTzPxwGFW7R7YuUdwyaHKI3pLvG1LvALsV21+G\n"
            + "K04xYp4XJvckgE8DYkrxlOexT3idAb46IaEb4oK8o1YR5Ye1dB/ZJoXKYYakVkok\n"
            + "akU/BFoSXyWeYkbGA08hstklbeJWISHYONWAYbaktdVl/XB1jx00WhJEAbRAGkVY\n"
            + "-----END RSA PRIVATE KEY-----\n");

    m.put(
        "rsa-private-3",
        "-----BEGIN RSA PRIVATE KEY-----\n"
            + "MIIEowIBAAKCAQEA7Wb9p0wqUwq5ZIpUG0+MgKwidb0TXeEVi86bhhoaHwzuwZPd\n"
            + "rZLanBCQCxp2gzp5WxW3huO91P89fXaX4IPqLWZn/s9aLxJk+ZiMfSrc49mJH99p\n"
            + "Z4/eHA9LyGNVvQ1Yj6WIrdQIMBypwyWTYqOBLsQp6Ouo7K0t5c0XhKJUDuebdRx9\n"
            + "WM7PSXVXr+u8BwL3+BW03lHp4tFgZhYae16mMV3DNlgHuBAusB6tQZT4yrn/lPhu\n"
            + "eTf2ie7pz2OVdjT9C5fZ+vRA23tvanusyP5j9zMGKR5sMSnPijwOLiOBPuMWcsFi\n"
            + "LeL+LY3uV0Ii5mtIbS78UUVmncrin/6u9Es1AwIDAQABAoIBAQCwgm2/8KJbYdLb\n"
            + "zPmh4LBvjwyEC9OVbmANtczulQOs6HmwVddxUYnWlX3zs3ZANb67GVd+JGAlOK0o\n"
            + "Vn+vv4Tiwow56UN9UijfZyu1eKQJiNkqaHq/NDmJFVpcIHdD++NH0mTgEZEQ7I7P\n"
            + "+GUv5q+K7PDYLDdJ2a0Rej6tL+Bdvym95munxONdtbb7WlIem74SzRYujKv8vlRL\n"
            + "8CwEs9xuf+RUgBChDHf80iSDzmpL3/CM9FONdQ17ieXCSMlGxfHSBDNlkIe21ODL\n"
            + "t/B5+KNCLmtzmcwQeQKIoyX9uMEMGfuZ/hirfkQ6qO7Ffq3fzFOMyz41XOfOaXcq\n"
            + "UgBXOj/JAoGBAPhCmcsTb9Jx4lOOH6UTVYPiFSJ9/7CBm9XewwHEcCmiKMW5LkZe\n"
            + "zO3WN3jwQrTr7eH6D/PH5KOIZ7+v9bV/vS/U+URo1bjP4ViibhdGMnzAJ8YPZ/3U\n"
            + "7/Kk3m1uGAP56vAdFI9ioqcoanfQNrUf5lxLv+DgvQjBcUPzxX4YSbFXAoGBAPTN\n"
            + "u2cNSMeAtUsVbaPr0DrShaemkJKs+4Ncb4kOcFkrDYez6mz+Y00TPfPkHJ5RSTn5\n"
            + "2XdzxkWG5zkFf8Ad5XMh8MhNZSwKILPrFibiCTwAS9OIB5/dcneEGBHxcSv9Pq2D\n"
            + "mYyUYEocqf0QRpg/5qwKElYViXViqpJtZz9CPbI1AoGAA6jHp4yjy1BOa7jekopU\n"
            + "als8wINm720ZpO9hpHcGyDZRr4hpPDRNhPvxWWEBOrV3jisnbQp3PknWbabkUkaN\n"
            + "vVTAT9fTvqOhyLKsOL+aIuiaLXswpzcqSkNP3AERbY2TfvKOyQZFK32XBCkXhVfx\n"
            + "B08+hswJPUXMq5m+QXuOKoUCgYBoeViOHUQ/KDW2ynlVKLFgOTIjH1m5zyszn4JW\n"
            + "KpxV4aLPlD/qrhIw9ZJOAL8Z7bTjkjZ13SnzyCPr2OXxVpDytrxsr2MLDXNxdVWp\n"
            + "2HN6cOHrb7VZS4era+td1P2oeVaDdJNWRIhneJ4vSv/lv/ew2keDB4P3XdlPznLu\n"
            + "s1VjNQKBgBZJxVm31P78875PIFcP8l5QXObxey6gF+1MtTblB54sXozItvgqtMHC\n"
            + "grMhGMdyANdgOWaor/Ti+74UXCO3wNPhiKtuc8tMs/fEPVGLwK1FDYWm6MHRhftJ\n"
            + "PBRaWgUQ9xa6BkPQOWzxZ/YWjlAV8182J6qji+0YoTWK5s7d6T2m\n"
            + "-----END RSA PRIVATE KEY-----\n");

    m.put(
        "rsa-private-4", // password: Apigee-IloveAPIs
        "-----BEGIN RSA PRIVATE KEY-----\n"
            + "Proc-Type: 4,ENCRYPTED\n"
            + "DEK-Info: DES-EDE3-CBC,171EA6A387A34BF7\n"
            + "\n"
            + "eoZdqVDEdtqvtlWWCYYNy3gGnK3bs5/y7nqw97Jf1NF0E2m8UzpinkR0w0HL5c7p\n"
            + "NvzJzHGtlntD9qd7E6hIdUsy96884rLXHmdehGDnPfPl223ofo6qq36pcaVyw6Nu\n"
            + "ImhLij4DtVoUTtiRqnhSje1MbM9nBOOGdNbgzi1QF7xvwoVq18g4QjyHF7SxV0hr\n"
            + "VLRjnIDqVig+HJgvp27nRc6mV+W4gVLKnuJaeBJpAW9harMzDA/kk8F0rbhHyLhJ\n"
            + "qfV9qx2uacXly8LgkVI/3wNgohelJ+YxSw+z27NzovgjJnhEnwXG5ZTZ502Ow/F8\n"
            + "GKsSPVw8g3UixI2g8L69nt1jAaE5sFCpzJkL1RO5+tqZ598SKOjnZpRqbMm+iPjm\n"
            + "DLjeSU1PKKeDx9E8J8QD1YFFJDlLQP2Lbsq8tx8xNwPOAwEixZqumftwoSFe2R0z\n"
            + "PtvlMpPvX08SvXz/OaysA3a+/sq6IizSZoKgq6S6dTrLx3GEPI4f1tWvirVbD87B\n"
            + "ImWNynNP2k6uG+Y1rpcdirKItp4iwLckMACuOAF5efB4rxDtce/h5dlqWY+JQ/UQ\n"
            + "IPsCxJjP4SiK+u4YZENhS9wZUhA1GRTFP84Q36tuTIb3Bdv5u01P6HxycbFyF0NU\n"
            + "Fx40Y4zcMMjGav8TR9vPlqgLqTYIpjPeydPqYZob5llBRMdCKVRtZfWSVKgjtemj\n"
            + "UjudYfgMovyvpzLiNVwFTUtuHQyqeZ92lQ9k5uRSMWhGKJxrEcYMl/laGiXIguwy\n"
            + "u/FSmzUco0wTSOKjJTXVHPD0fZYctd7l114uqGH0zO6SZjIiBWiDOW/q7Onpn4A+\n"
            + "Elt1u/bVb8wZBr8chFGaMUfd6TW2LieOa23W2X1KxXZhynT2s7PZn3IIu2TJtM8r\n"
            + "3ylQvZaHZRoDjexCZY7Ry1/J60hxDkSP1KZLpEekYwYTfJPHh0OWaHtWTAkOqOT9\n"
            + "4WFAAnUqXpH+HOsiht7IFibepIghnMg6FOTZVgIgP5lAdHGDjbzCS7VuvGYQ/O6b\n"
            + "exVCmUB4MV6qcHtiwsDV6QWukBRfdY8OZniMaSVpV/X14QKj3PmXIpxyrGXKOK4m\n"
            + "OZedGRkLaTz9quF0+Vf1JSog6upw4qLpnge0HJz5x1XMcnpvlw0PjXnrNIo/Rj7O\n"
            + "WMsfFACnvaQyJXTk3Ul/MKUhuwRGtgD3htAIqpX91hMf+89JeE4ThaAcLfL2Mbit\n"
            + "sU3JLxEmNTIz6+GjQgeU/fZU2xg8gBnyCIh2CfpyhiyjfyWol+76TBqgFpz+QNGf\n"
            + "UYB9J4xbsVDc8XFhUBd0mY1pWASqREuU+qeDbx8DSqvun7YbP4Px5HzK+h+o1gV6\n"
            + "Ge4GFh3FIpwwKdZRxTpvKkE/0A3O1HOAUppvrERjWhdZcpDCRYP7R90k+B3FIVCT\n"
            + "ddUnryiJ/SmEEApn5swcJueLZgkBJluW1dg2RHYQcKu64wrKq66PmwaVOFo/T7bD\n"
            + "O8OPnhSgbxM+UdZPwmr7aKeoLPg9YvT2PJbKumQ68BDgrTWav/eUAElY3bNL+pf7\n"
            + "W6dD5I+Izacqn03jJgbDnIpdtFW3zsC1MYesfavVtRmdKlyV1fZBPDl5+F/kSCv1\n"
            + "-----END RSA PRIVATE KEY-----\n");

    privateKeyMap = java.util.Collections.unmodifiableMap(m);
  }

  @BeforeMethod()
  public void testSetup1() {

    msgCtxt =
        new MockUp<MessageContext>() {
          private Map variables;

          public void $init() {
            variables = new HashMap();
          }

          @Mock()
          public <T> T getVariable(final String name) {
            if (variables == null) {
              variables = new HashMap();
            }
            T value = (T) variables.get(name);
            System.out.printf(
                "getVariable(%s) = %s\n", name, (value == null) ? "null" : value.toString());
            return value;
          }

          @Mock()
          public boolean setVariable(final String name, final Object value) {
            if (variables == null) {
              variables = new HashMap();
            }
            System.out.printf(
                "setVariable(%s) := %s\n", name, (value == null) ? "null" : value.toString());
            variables.put(name, value);
            return true;
          }

          @Mock()
          public boolean removeVariable(final String name) {
            if (variables == null) {
              variables = new HashMap();
            }
            if (variables.containsKey(name)) {
              variables.remove(name);
            }
            return true;
          }
        }.getMockInstance();

    exeCtxt = new MockUp<ExecutionContext>() {}.getMockInstance();
  }
}
