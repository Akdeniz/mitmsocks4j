package com.akdeniz.mitmsocks4j.misc;

import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.X509V3CertificateGenerator;

/**
 * Some certificate generating functions in case user may want to generate specific CA certificate.
 * 
 * @author akdeniz
 * 
 */
@SuppressWarnings("deprecation")
public class CertificateGenerator {
    
    static{
	Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) throws Exception {

	generateCACert();
    }

    private static void generateCACert() throws Exception {
	String domainName = "CN=MItMSocks4J, O=akdeniz, OU=com";

	KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
	keyPairGenerator.initialize(1024);
	KeyPair KPair = keyPairGenerator.generateKeyPair();

	X509V3CertificateGenerator v3CertGen = new X509V3CertificateGenerator();

	// generate a serial number for certificate
	SecureRandom secureRandom = new SecureRandom();
	byte[] serial = new byte[16];
	secureRandom.nextBytes(serial);
	BigInteger serialNumber = new BigInteger(serial);
	if (serialNumber.signum() < 0) {
	    serialNumber = serialNumber.negate();
	}
	
	v3CertGen.setSerialNumber(serialNumber);
	v3CertGen.setIssuerDN(new X509Principal(domainName));
	v3CertGen.setNotBefore(new Date(System.currentTimeMillis() - 1000L * 60 * 60 * 24 * 30));
	v3CertGen.setNotAfter(new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 365 * 10)));
	v3CertGen.setSubjectDN(new X509Principal(domainName));

	v3CertGen.addExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(true, 1));

	v3CertGen.setPublicKey(KPair.getPublic());
	v3CertGen.setSignatureAlgorithm("SHA1WithRSA");

	X509Certificate PKCertificate = v3CertGen.generateX509Certificate(KPair.getPrivate());

	// Dump certificate
	FileOutputStream fos = new FileOutputStream("mitmsocks4j.cer");
	fos.write(PKCertificate.getEncoded());
	fos.close();

	// Create a keystore
	KeyStore privateKS = KeyStore.getInstance("JKS");
	privateKS.load(null);

	privateKS.setKeyEntry("sample.alias", KPair.getPrivate(), new char[] { '1', '2', '3', '4', '5', '6' },
		new java.security.cert.Certificate[] { PKCertificate });
	FileOutputStream ksFos = new FileOutputStream("mitmsocks4j_ca.jks");
	privateKS.store(ksFos, new char[] { '1', '2', '3', '4', '5', '6' });
	ksFos.close();
    }
}
