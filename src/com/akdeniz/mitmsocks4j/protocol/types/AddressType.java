package com.akdeniz.mitmsocks4j.protocol.types;

/**
 * @author akdeniz
 */
public enum AddressType {
    IPV4((byte) 1), DOMAINNAME((byte) 3), IPV6((byte) 4), NOT_SUPPORTED((byte) 0xFF);

    public byte value;

    AddressType(byte value) {
	this.value = value;
    }

    public static AddressType valueOf(byte value) {
	for (AddressType atype : values()) {
	    if (atype.value == value) {
		return atype;
	    }
	}
	return NOT_SUPPORTED;
    }
}
