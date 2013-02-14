package com.akdeniz.mitmsocks4j.protocol.messages;

import java.net.InetAddress;
import java.net.UnknownHostException;
import org.apache.mina.core.buffer.IoBuffer;

import com.akdeniz.mitmsocks4j.protocol.types.AddressType;
import com.akdeniz.mitmsocks4j.protocol.types.Command;
import com.akdeniz.mitmsocks4j.protocol.types.SocksVersion;

/**
 * Informs server about commands to be performed and address-port pair to be
 * used with this command.
 * 
 * @author akdeniz
 * 
 */
public class ClientRequest {

    public SocksVersion version;
    public Command command;
    public byte reserved;
    public AddressType addressType;
    public InetAddress destAddress;
    public int destPort;

    public ClientRequest() {
    }

    public ClientRequest(SocksVersion version, Command command, byte reserved, AddressType addressType, byte[] destAddress,
	    short destPort) {
	this.version = version;
	this.command = command;
	this.reserved = reserved;
	this.addressType = addressType;
	setDestAddress(destAddress, addressType);
	this.destPort = destPort;
    }

    public boolean decode(IoBuffer in) {
	if (in.remaining() > 4) {
	    in.mark();
	    version = SocksVersion.valueOf(in.get());
	    command = Command.valueOf(in.get());
	    reserved = in.get();
	    addressType = AddressType.valueOf(in.get());

	    switch (addressType) {
	    case IPV4:
		if (in.remaining() > 4) {
		    byte[] destAddress = new byte[4];
		    in.get(destAddress);
		    setDestAddress(destAddress, AddressType.IPV4);
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
		    setDestAddress(destAddress, AddressType.DOMAINNAME);
		} else {
		    in.reset();
		    return false;
		}
		break;
	    case IPV6:
		if (in.remaining() > 16) {
		    byte[] destAddress = new byte[16];
		    in.get(destAddress);
		    setDestAddress(destAddress, AddressType.IPV6);
		} else {
		    in.reset();
		    return false;
		}
		break;
	    }

	    if (in.remaining() >= 2) {
		destPort = in.getShort() & 0xffff;
	    } else {
		in.reset();
		return false;
	    }

	    return true;
	} else {
	    return false;
	}
    }

    public void setDestAddress(byte[] destAddress, AddressType type) {
	try {
	    if (type == AddressType.DOMAINNAME) {
		this.destAddress = InetAddress.getByName(new String(destAddress));
	    } else {
		this.destAddress = InetAddress.getByAddress(destAddress);
	    }
	} catch (UnknownHostException e) {
	    throw new IllegalArgumentException(e);
	}
    }

    @Override
    public String toString() {
	return "ClientRequest[ version=" + version + ", command=" + command + ", reserved=" + reserved + ", addressType="
		+ addressType + ", destAddress=" + destAddress + ", destPort=" + destPort + " ]";
    }
}