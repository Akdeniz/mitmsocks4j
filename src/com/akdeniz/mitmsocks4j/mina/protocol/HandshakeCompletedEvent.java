package com.akdeniz.mitmsocks4j.mina.protocol;

import java.security.Principal;
import java.security.cert.Certificate;

import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.security.cert.X509Certificate;

import org.apache.mina.core.session.IoSession;

/**
 * 
 * @author akdeniz
 *
 */
public class HandshakeCompletedEvent {
    
    private final IoSession ioSession;
    private final SSLSession sslSession;

    public HandshakeCompletedEvent(IoSession ioSession, SSLSession sslSession)
    {
	this.ioSession = ioSession;
	this.sslSession = sslSession;
    }

    public IoSession getIoSession() {
	return ioSession;
    }

    public SSLSession getSslSession() {
	return sslSession;
    }
    
    public String getCipherSuite() {
        return sslSession.getCipherSuite();
    }

    public Certificate[] getLocalCertificates() {
        return sslSession.getLocalCertificates();
    }

    public Certificate[] getPeerCertificates() throws SSLPeerUnverifiedException {
        return sslSession.getPeerCertificates();
    }

    public X509Certificate[] getPeerCertificateChain() throws SSLPeerUnverifiedException {
        return sslSession.getPeerCertificateChain();
    }

    public Principal getPeerPrincipal() throws SSLPeerUnverifiedException {
        return sslSession.getPeerPrincipal();
    }

    public Principal getLocalPrincipal() {
        return sslSession.getLocalPrincipal();
    }
}
