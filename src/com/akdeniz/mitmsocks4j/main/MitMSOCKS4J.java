package com.akdeniz.mitmsocks4j.main;

import java.util.ArrayList;
import java.util.List;

import net.sourceforge.argparse4j.ArgumentParsers;
import net.sourceforge.argparse4j.inf.ArgumentParser;
import net.sourceforge.argparse4j.inf.ArgumentParserException;
import net.sourceforge.argparse4j.inf.FeatureControl;
import net.sourceforge.argparse4j.inf.Namespace;

import org.slf4j.LoggerFactory;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;

import com.akdeniz.mitmsocks4j.protocol.ProxyServer;

/**
 * Man in the Middle SOCKS Proxy for JAVA
 * 
 * @author akdeniz
 *
 */
public class MitMSOCKS4J {

    private static final String DEFAULT_PASSWORD = "123456";
    private static final String DEFAULT_KEYSTORE = "mitmsocks4j.jks";
    private static final int DEFAULT_PROXY_PORT = 1080;
    private static final int DEFAULT_DELEGATOR_PORT = 1081;

    private ArgumentParser parser;
    private Namespace namespace;

    public MitMSOCKS4J() {
	parser = ArgumentParsers.newArgumentParser("mitmsocks4j").description("Strips SSL/TLS layer from SOCKS proxy connection to dump plain data!");

	parser.addArgument("-l", "--loglevel").required(false).nargs("?").choices("ALL", "TRACE", "DEBUG", "INFO", "WARN", "ERROR", "OFF")
		.help("Sets logging level!").setDefault("OFF");

	parser.addArgument("-x", "--proxyport").required(false).nargs("?").help("Proxy port that proxy listens.(default:" + DEFAULT_PROXY_PORT + ")")
		.type(Integer.class).setDefault(DEFAULT_PROXY_PORT);
	parser.addArgument("-d", "--delegatorport").required(false).nargs("?")
		.help("Delegator port that mitm takes place.(default:" + DEFAULT_DELEGATOR_PORT + ")").type(Integer.class).setDefault(DEFAULT_DELEGATOR_PORT);
	parser.addArgument("-s", "--securedports").required(false).nargs("*").help("Secured ports that will be ssl-stripped").type(Integer.class)
		.setDefault(FeatureControl.SUPPRESS);
	parser.addArgument("-k", "--keystore").required(false).help("Keystore that will be used to imitate actual server certificates for clients(default:"+DEFAULT_KEYSTORE+")")
		.setDefault(DEFAULT_KEYSTORE);
	parser.addArgument("-p", "--password").required(false).help("Keystore password.(default:"+DEFAULT_PASSWORD+")").setDefault(DEFAULT_PASSWORD);
    }

    public void operate(String[] argv) throws Exception {
	try {
	    namespace = parser.parseArgs(argv);
	} catch (ArgumentParserException e) {
	    System.err.println(e.getMessage());
	    parser.printHelp();
	    System.exit(-1);
	}

	String loglevel = namespace.getString("loglevel");
	setLogLevel(loglevel);

	int proxyPort = namespace.getInt("proxyport");
	int delegatorPort = namespace.getInt("delegatorport");
	List<Integer> securedPorts = namespace.getList("securedports");
	securedPorts = securedPorts != null ? securedPorts : new ArrayList<Integer>();
	String keystore = namespace.getString("keystore");
	char[] password = namespace.getString("password").toCharArray();

	ProxyServer proxyServer = new ProxyServer(proxyPort, delegatorPort, securedPorts, keystore, password);
	proxyServer.start();

	String securedPortsStr = "[";
	for (Integer securedPort : securedPorts) {
	    securedPortsStr += (securedPort + ",");
	}
	securedPortsStr += "]";

	System.out.println("Proxy started. [proxyPort = " + proxyPort + ", delegatorPort=" + delegatorPort + ", securedPorts=" + securedPortsStr + "]");
    }

    private static void setLogLevel(String loglevel) {
	Logger loggerRoot = (Logger) LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);
	switch (loglevel) {
	case "ALL":
	    loggerRoot.setLevel(Level.ALL);
	    break;
	case "TRACE":
	    loggerRoot.setLevel(Level.TRACE);
	    break;
	case "DEBUG":
	    loggerRoot.setLevel(Level.DEBUG);
	    break;
	case "INFO":
	    loggerRoot.setLevel(Level.INFO);
	    break;
	case "WARN":
	    loggerRoot.setLevel(Level.WARN);
	    break;
	case "ERROR":
	    loggerRoot.setLevel(Level.ERROR);
	    break;
	case "OFF":
	    loggerRoot.setLevel(Level.OFF);
	    break;
	}
    }

    public static void main(String[] args) {
	try {
	    new MitMSOCKS4J().operate(args);
	} catch (Exception e) {
	    System.err.println(e.getMessage());
	}
    }
}
