package com.akdeniz.mitmsocks4j.protocol.messages;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;

import com.akdeniz.mitmsocks4j.protocol.types.AuthenticationMethod;
import com.akdeniz.mitmsocks4j.protocol.types.SocksVersion;

/**
 * Informs client about selected {@link SocksVersion} and {@link AuthenticationMethod}
 * 
 * @author akdeniz
 *
 */
public class ServerHello implements Encodable {
    public SocksVersion version;
    public AuthenticationMethod method;

    public ServerHello(SocksVersion version, AuthenticationMethod method) {
	this.version = version;
	this.method = method;
    }

    public byte[] getEncoded() {
	try {
	    ByteArrayOutputStream baos = new ByteArrayOutputStream();
	    DataOutputStream daos = new DataOutputStream(baos);
	    daos.write(version.value);
	    daos.write(method.value);
	    daos.flush();
	    return baos.toByteArray();
	} catch (IOException e) {
	    return null; // never happens!
	}
    }
}