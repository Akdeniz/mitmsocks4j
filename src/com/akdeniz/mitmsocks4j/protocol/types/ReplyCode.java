package com.akdeniz.mitmsocks4j.protocol.types;

/**
 * 
 * @author akdeniz
 *
 */
public enum ReplyCode {
    SUCCESS((byte) 0), GENERAL((byte) 1), NOT_ALLOWED((byte) 2), NETWORK_UNREACHABLE((byte) 3), HOST_UNREACHABLE((byte) 4), CONNECTION_REFUSED(
	    (byte) 5), TTL_EXPIRED((byte) 6), COMMAND_NOT_SUPPORTED((byte) 7), ADDRESS_TYPE_NOT_SUPPORTED((byte) 8);

    public byte value;

    ReplyCode(byte value) {
	this.value = value;
    }

    public static ReplyCode valueOf(byte value) {
	for (ReplyCode code : values()) {
	    if (code.value == value) {
		return code;
	    }
	}
	throw new IllegalArgumentException("Not a valid reply code");
    }
}
