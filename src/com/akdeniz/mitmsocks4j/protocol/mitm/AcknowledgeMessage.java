package com.akdeniz.mitmsocks4j.protocol.mitm;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;

import org.apache.mina.core.buffer.IoBuffer;

import com.akdeniz.mitmsocks4j.protocol.Delegator;
import com.akdeniz.mitmsocks4j.protocol.ProxyServer;
import com.akdeniz.mitmsocks4j.protocol.messages.Encodable;
import com.akdeniz.mitmsocks4j.protocol.types.AddressType;

/**
 * {@link Delegator}'s acknowledge message to inform {@link ProxyServer} that
 * remote connection is ready.
 * 
 * @author akdeniz
 * 
 */
public class AcknowledgeMessage implements Encodable {

    private InetAddress address;
    private int port;
    private AddressType addressType;

    public AcknowledgeMessage() {
    }

    public AcknowledgeMessage(InetAddress address, int port) {
	if (address instanceof Inet4Address) {
	    addressType = AddressType.IPV4;
	} else if (address instanceof Inet6Address) {
	    addressType = AddressType.IPV6;
	}
	this.address = address;
	this.port = port;

    }

    @Override
    public byte[] getEncoded() {
	try {
	    ByteArrayOutputStream baos = new ByteArrayOutputStream();
	    DataOutputStream daos = new DataOutputStream(baos);
	    daos.write(addressType.value);
	    daos.write(address.getAddress());
	    daos.writeShort(port);
	    daos.flush();
	    byte[] data = baos.toByteArray();
	    return data;
	} catch (IOException e) {
	    return null; // never happens!
	}
    }

    public boolean decode(IoBuffer in) {
	if (in.remaining() > 1) {
	    in.mark();
	    addressType = AddressType.valueOf(in.get());

	    switch (addressType) {
	    case IPV4:
		if (in.remaining() > 4) {
		    byte[] destAddress = new byte[4];
		    in.get(destAddress);
		    setAddress(destAddress);
		} else {
		    in.reset();
		    return false;
		}
		break;
	    case DOMAINNAME:
		if (in.prefixedDataAvailable(1, 512)) {
		    byte len = in.get();
		    byte[] destAddress = new byte[len];
		    in.get(destAddress);
		    setAddress(destAddress);
		} else {
		    in.reset();
		    return false;
		}
		break;
	    case IPV6:
		if (in.remaining() > 16) {
		    byte[] destAddress = new byte[16];
		    in.get(destAddress);
		    setAddress(destAddress);
		} else {
		    in.reset();
		    return false;
		}
		break;
	    }

	    if (in.remaining() >= 2) {
		port = in.getShort() & 0xffff;
	    } else {
		in.reset();
		return false;
	    }

	    return true;
	} else {
	    return false;
	}
    }

    public void setAddress(byte[] destAddress) {
	try {
	    this.address = InetAddress.getByAddress(destAddress);
	} catch (UnknownHostException e) {
	    throw new IllegalArgumentException(e);
	}
    }

    @Override
    public String toString() {
	return "ACKNOWLEDGEMSG[ addr=" + address + ", port=" + port + "]";
    }
}
