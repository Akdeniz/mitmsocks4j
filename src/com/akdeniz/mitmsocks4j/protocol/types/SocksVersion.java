package com.akdeniz.mitmsocks4j.protocol.types;

/**
 * 
 * @author akdeniz
 *
 */
public enum SocksVersion {
    SOCKSv4((byte) 4), SOCKSv5((byte) 5), UNKNOWN((byte) 0xff);

    public byte value;

    private SocksVersion(byte value) {
	this.value = value;
    }

    public static SocksVersion valueOf(byte value) {
	for (SocksVersion version : values()) {
	    if (version.value == value) {
		return version;
	    }
	}
	return UNKNOWN;
    }
}
