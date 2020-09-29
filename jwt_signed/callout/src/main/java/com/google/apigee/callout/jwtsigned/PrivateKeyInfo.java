package com.google.apigee.callout.jwtsigned;

import com.apigee.flow.message.MessageContext;

public class PrivateKeyInfo {
        public PrivateKeyInfo(MessageContext msgCtxt, byte[] keyBytes, String password) {
            this.msgCtxt = msgCtxt;
            this.keyBytes = keyBytes;
            this.password = password;
        }
        //public PrivateKeyInfo(byte[] bytes, String p) { keyBytes = bytes; password = p;}
        public MessageContext msgCtxt;
        public byte[] keyBytes;
        public String password;
    }
