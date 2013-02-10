package com.akdeniz.mitmsocks4j.misc;

import java.security.Key;
import java.security.cert.Certificate;
/**
 * 
 * @author akdeniz
 *
 */
public class KeyCertPair{
	private final Key key;
	private final Certificate certificate;

	public KeyCertPair(Certificate certificate, Key key) {
	    this.certificate = certificate;
	    this.key = key;
	}

	public Key getKey() {
	    return key;
	}

	public Certificate getCertificate() {
	    return certificate;
	}
}
