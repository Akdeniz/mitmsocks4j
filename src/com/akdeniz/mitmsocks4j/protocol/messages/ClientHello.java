package com.akdeniz.mitmsocks4j.protocol.messages;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.apache.mina.core.buffer.IoBuffer;

import com.akdeniz.mitmsocks4j.protocol.types.AuthenticationMethod;
import com.akdeniz.mitmsocks4j.protocol.types.SocksVersion;

/**
 * Represents SOCKS protocol first message to agree with version and
 * authentication with proxy server.
 * 
 * @author akdeniz
 * 
 */
public class ClientHello {

    public SocksVersion version;
    public byte nmethods;
    public List<AuthenticationMethod> methods;

    public ClientHello() {
    }

    public ClientHello(SocksVersion version, byte nmethods, byte[] methods) {
	this.version = version;
	this.nmethods = nmethods;
	setMethods(methods);
    }

    public void setMethods(byte[] methodsArray) {
	this.methods = new ArrayList<AuthenticationMethod>();
	for (byte method : methodsArray) {
	    AuthenticationMethod authMethod = AuthenticationMethod.valueOf(method);
	    if (authMethod != AuthenticationMethod.UNKNOWN) {
		methods.add(authMethod);
	    }
	}
    }

    public boolean decode(IoBuffer buffer) {
	buffer.mark();
	version = SocksVersion.valueOf(buffer.get());
	if (buffer.prefixedDataAvailable(1, 255)) {
	    nmethods = buffer.get();
	    byte[] methodsArray = new byte[nmethods];
	    buffer.get(methodsArray);
	    setMethods(methodsArray);
	    return true;
	} else {
	    buffer.reset();
	    return false;
	}
    }

    @Override
    public String toString() {
	return "ClientHello[ version=" + version + ", nmethods=" + nmethods + ", methods=" + Arrays.toString(methods.toArray())
		+ " ]";
    }
}
