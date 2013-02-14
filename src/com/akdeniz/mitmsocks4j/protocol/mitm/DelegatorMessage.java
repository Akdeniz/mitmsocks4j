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
import com.akdeniz.mitmsocks4j.protocol.messages.Encodable;
import com.akdeniz.mitmsocks4j.protocol.types.AddressType;
import com.akdeniz.mitmsocks4j.protocol.types.Command;

/**
 * Informs {@link Delegator} about remote address-port pair that command to be executed with.
 * 
 * This message also defines if remote connection will be secure.
 * 
 * @author akdeniz
 *
 */
public class DelegatorMessage implements Encodable {

    private InetAddress address;
    private int port;
    private boolean ssl;
    private AddressType addressType;
    private Command command;

    public DelegatorMessage(Command command, InetAddress address, int port, boolean ssl) {
	this.command = command;
	if (address instanceof Inet4Address) {
	    addressType = AddressType.IPV4;
	} else if (address instanceof Inet6Address) {
	    addressType = AddressType.IPV6;
	}
	this.address = address;
	this.port = port;
	this.ssl = ssl;
    }

    public DelegatorMessage() {
    }

    @Override
    public byte[] getEncoded() {
	try {
	    ByteArrayOutputStream baos = new ByteArrayOutputStream();
	    DataOutputStream daos = new DataOutputStream(baos);
	    daos.write(command.value);
	    daos.write(addressType.value);
	    daos.write(address.getAddress());
	    daos.writeShort(port);
	    daos.writeBoolean(ssl);
	    daos.flush();
	    byte[] data = baos.toByteArray();
	    return data;
	} catch (IOException e) {
	    return null; // never happens!
	}
    }

    public boolean decode(IoBuffer in) {
	if (in.remaining() > 2) {
	    in.mark();
	    this.command = Command.valueOf(in.get());
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

	    if (in.remaining() > 2) {
		port = in.getShort() & 0xffff;
	    } else {
		in.reset();
		return false;
	    }

	    if (in.remaining() >= 1) {
		ssl = in.get() == 1;
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

    public InetAddress getAddress() {
	return address;
    }

    public int getPort() {
	return port;
    }

    public boolean isSSL() {
	return ssl;
    }

    @Override
    public String toString() {
	return "DELEGATORMSG[ command=" + command + ", addr=" + address + ", port=" + port + ", ssl=" + ssl + " ]";
    }

    public Command getCommand() {
	return command;
    }
}
