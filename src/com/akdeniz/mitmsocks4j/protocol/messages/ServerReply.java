package com.akdeniz.mitmsocks4j.protocol.messages;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;

import com.akdeniz.mitmsocks4j.protocol.types.AddressType;
import com.akdeniz.mitmsocks4j.protocol.types.Command;
import com.akdeniz.mitmsocks4j.protocol.types.ReplyCode;
import com.akdeniz.mitmsocks4j.protocol.types.SocksVersion;

/**
 * Server's reply with the result of performed {@link Command}. 
 * @author akdeniz
 *
 */
public class ServerReply implements Encodable {

    public SocksVersion version;
    public ReplyCode replyCode;
    public byte reserved = 0;
    public AddressType addressType;
    public byte[] bindAddress;
    public short bindPort;

    // XXX : handle DOMAINNAME address type!
    public ServerReply(SocksVersion version, ReplyCode code, InetAddress bindAddress, short bindPort) {
	this.version = version;
	replyCode = code;

	if (replyCode == ReplyCode.SUCCESS) {
	    if (bindAddress instanceof Inet4Address) {
		addressType = AddressType.IPV4;
	    } else if (bindAddress instanceof Inet6Address) {
		addressType = AddressType.IPV6;
	    }
	    this.bindAddress = bindAddress.getAddress();
	    this.bindPort = bindPort;
	} else {
	    addressType = AddressType.IPV4;
	    this.bindAddress = new byte[] { 0, 0, 0, 0 };
	    bindPort = 0;
	}
    }

    public byte[] getEncoded() {
	try {
	    ByteArrayOutputStream baos = new ByteArrayOutputStream();
	    DataOutputStream daos = new DataOutputStream(baos);
	    daos.write(version.value);
	    daos.write(replyCode.value);
	    daos.write(reserved);
	    daos.write(addressType.value);
	    daos.write(bindAddress);
	    daos.writeShort(bindPort);
	    daos.flush();
	    byte[] data = baos.toByteArray();
	    return data;
	} catch (IOException e) {
	    return null; // never happens!
	}
    }
}
