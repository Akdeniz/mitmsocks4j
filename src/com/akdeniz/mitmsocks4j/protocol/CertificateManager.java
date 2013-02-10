package com.akdeniz.mitmsocks4j.protocol;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyManagementException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Enumeration;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;

import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.X509V3CertificateGenerator;

import com.akdeniz.mitmsocks4j.misc.KeyCertPair;

/**
 * Delegator's certificate manager.
 * 
 * It is used for forging remote servers' certificate on-the-fly.
 * 
 * @author akdeniz
 * 
 */
@SuppressWarnings("deprecation")
public class CertificateManager {

    static {
	Security.addProvider(new BouncyCastleProvider());
    }

    private final char[] password;
    static KeyCertPair issuerCA;
    private static KeyStore keyStore;

    private final SSLContext clientSSLContext;

    public CertificateManager(String keystorePath, char[] password) throws Exception {

	this.password = password;

	keyStore = KeyStore.getInstance("JKS");
	keyStore.load(new FileInputStream(keystorePath), password);
	issuerCA = extractIssuer();
	clientSSLContext = createClientSSLContext();
    }

    /**
     * Generates certificate and public-private key pair with given
     * certificate's attributes and build SSL context out of them.
     */
    public SSLContext createServerSSLContext(X509Certificate peerCert) throws Exception {

	KeyCertPair keyCertPair = imitatePeerCertificate(peerCert);

	KeyStore serverKS = KeyStore.getInstance("JKS");
	serverKS.load(null);
	serverKS.setKeyEntry("akdeniz", keyCertPair.getKey(), password,
		new java.security.cert.Certificate[] { keyCertPair.getCertificate() });

	SSLContext sslcontext = SSLContext.getInstance("SSL");
	KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
	kmf.init(serverKS, password);
	sslcontext.init(kmf.getKeyManagers(), new TrustManager[] { new DummyX509TrustManager() }, null);
	return sslcontext;
    }

    /**
     * Generates certificate and public-private key pair with given
     * certificate's attributes and build SSL context out of them.
     */
    public SSLContext createServerSSLContext(javax.security.cert.X509Certificate peerCert) throws Exception {
	CertificateFactory certificateFactory = CertificateFactory.getInstance("X509");
	ByteArrayInputStream bais = new ByteArrayInputStream(peerCert.getEncoded());
	X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(bais);
	return createServerSSLContext(certificate);
    }

    /**
     *  Creates a SSL context with no trust check.
     */
    private SSLContext createClientSSLContext() throws NoSuchAlgorithmException, UnrecoverableKeyException, KeyStoreException,
	    KeyManagementException {

	SSLContext sslcontext = SSLContext.getInstance("SSL");
	KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
	kmf.init(keyStore, password);
	sslcontext.init(kmf.getKeyManagers(), new TrustManager[] { new DummyX509TrustManager() }, null);
	return sslcontext;
    }

    /**
     * Forges a certificate with given certificate's attributes and signs it with CA of proxy.
     */
    private static KeyCertPair imitatePeerCertificate(X509Certificate cert2Imitate) throws Exception {

	// TODO imitate key algorithm also
	// (cert2Imitate.getPublicKey().getAlgorithm())
	KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
	keyPairGenerator.initialize(1024);
	KeyPair keyPair = keyPairGenerator.generateKeyPair();

	X509V3CertificateGenerator v3CertGen = new X509V3CertificateGenerator();

	SecureRandom secureRandom = new SecureRandom();
	byte[] serial = new byte[16];
	secureRandom.nextBytes(serial);
	BigInteger serialNumber = new BigInteger(serial);
	if (serialNumber.signum() < 0) {
	    serialNumber = serialNumber.negate();
	}
	v3CertGen.setSerialNumber(serialNumber);
	v3CertGen.setIssuerDN(((X509Certificate) issuerCA.getCertificate()).getIssuerX500Principal());
	v3CertGen.setNotBefore(new Date(System.currentTimeMillis() - 1000L * 60 * 60 * 24 * 30));
	v3CertGen.setNotAfter(new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 365 * 10)));
	v3CertGen.setSubjectDN(cert2Imitate.getSubjectX500Principal());

	ExtendedKeyUsage extendedKeyUsage = new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth);
	v3CertGen.addExtension(X509Extensions.ExtendedKeyUsage, false, extendedKeyUsage);
	v3CertGen.addExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));

	v3CertGen.setPublicKey(keyPair.getPublic());
	v3CertGen.setSignatureAlgorithm("SHA1WithRSA");

	Certificate pkCertificate = v3CertGen.generateX509Certificate((PrivateKey) issuerCA.getKey());

	return new KeyCertPair(pkCertificate, keyPair.getPrivate());
    }

    private KeyCertPair extractIssuer() throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException {

	Enumeration<String> aliases = keyStore.aliases();
	while (aliases.hasMoreElements()) {
	    String alias = aliases.nextElement();
	    Certificate certificate = keyStore.getCertificate(alias);
	    Key key = keyStore.getKey(alias, password);
	    return new KeyCertPair(certificate, key);
	}

	return null;
    }

    /**
     * Gets ssl contex with no trust check.
     */
    public SSLContext getClientSSLContext() {
	return clientSSLContext;
    }
}
