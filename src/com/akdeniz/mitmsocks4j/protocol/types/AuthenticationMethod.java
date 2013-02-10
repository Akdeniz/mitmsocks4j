package com.akdeniz.mitmsocks4j.protocol.types;
/**
 * 
 * @author akdeniz
 *
 */
public enum AuthenticationMethod {
    NOAUTH((byte) 0), GSSAPI((byte) 1), USERNAME_PASSWORD((byte) 2), NO_ACCEPTABLE_METHODS((byte) 0xff), UNKNOWN((byte) 0xfe);
    public byte value;

    AuthenticationMethod(byte value) {
	this.value = value;
    }

    public static AuthenticationMethod valueOf(byte value) {
	for (AuthenticationMethod method : values()) {
	    if (method.value == value) {
		return method;
	    }
	}
	return UNKNOWN;
    }
}
