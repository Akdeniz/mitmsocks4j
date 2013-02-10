package com.akdeniz.mitmsocks4j.protocol;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import javax.net.ssl.SSLContext;
import javax.security.cert.X509Certificate;

import org.apache.mina.core.buffer.IoBuffer;
import org.apache.mina.core.future.ConnectFuture;
import org.apache.mina.core.future.IoFutureListener;
import org.apache.mina.core.service.IoHandler;
import org.apache.mina.core.service.IoProcessor;
import org.apache.mina.core.session.IoSession;
import org.apache.mina.filter.codec.ProtocolCodecFilter;
import org.apache.mina.filter.ssl.SslFilter;
import org.apache.mina.transport.socket.SocketAcceptor;
import org.apache.mina.transport.socket.nio.NioDatagramConnector;
import org.apache.mina.transport.socket.nio.NioSession;
import org.apache.mina.transport.socket.nio.NioSocketAcceptor;
import org.apache.mina.transport.socket.nio.NioSocketConnector;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.akdeniz.mitmsocks4j.mina.protocol.DelegatorLocalCodecFactory;
import com.akdeniz.mitmsocks4j.mina.protocol.HandshakeCompletedEvent;
import com.akdeniz.mitmsocks4j.mina.protocol.HandshakeCompletedListener;
import com.akdeniz.mitmsocks4j.mina.protocol.DelegatorRemoteCodecFactory;
import com.akdeniz.mitmsocks4j.misc.HexDumpEncoder;
import com.akdeniz.mitmsocks4j.protocol.mitm.AcknowledgeMessage;
import com.akdeniz.mitmsocks4j.protocol.mitm.DelegatorMessage;

/**
 * This is the class that all man-in-the-middle operations take place.
 * 
 * Basically this class acts as a bridge between proxy and remote server and dumps content of connections to file.
 * 
 * If connection is secure, it generates a certificate on-the-fly with remote server's certificate attributes.
 * 
 * @author akdeniz
 *
 */
public class Delegator extends AbstractIoHandler {

    private static Logger LOGGER = LoggerFactory.getLogger(Delegator.class);

    private static final String SSLFILTER = "sslfilter";
    private final Map<IoSession, IoSession> sessionMap = new ConcurrentHashMap<IoSession, IoSession>(3);
    private final Map<Integer, SSLContext> certificateMap = new ConcurrentHashMap<Integer, SSLContext>(3);

    public static final long TIMEOUT = 20000;
    private static final int IDLE_TIMEOUT = 180000;

    private SocketAcceptor acceptor;
    private IoProcessor<NioSession> ioProcessor;

    private final CertificateManager certificateManager;

    public Delegator(IoProcessor<NioSession> ioProcessor, CertificateManager certificateManager) {
	this.ioProcessor = ioProcessor;
	this.certificateManager = certificateManager;
	acceptor = new NioSocketAcceptor(ioProcessor);
	acceptor.getFilterChain().addLast("codec", new ProtocolCodecFilter(new DelegatorRemoteCodecFactory()));
	acceptor.setReuseAddress(true);
	acceptor.setHandler(this);
    }

    public Socket newSocket() throws IOException {
	Socket socket = new Socket(getServerAddress(), getServerPort());
	socket.setSoTimeout(IDLE_TIMEOUT);
	return socket;
    }

    public ConnectFuture newSession(IoHandler ioHandler) {
	NioSocketConnector connector = new NioSocketConnector(this.ioProcessor);
	connector.getFilterChain().addLast("codec", new ProtocolCodecFilter(new DelegatorLocalCodecFactory()));
	connector.setHandler(ioHandler);
	return connector.connect(new InetSocketAddress(getServerAddress(), getServerPort()));
    }

    public void start(int port) throws IOException {
	acceptor.bind(new InetSocketAddress(port));
    }

    public void stop() {
	acceptor.unbind();
	acceptor.dispose();
    }

    public InetAddress getServerAddress() {
	return acceptor.getLocalAddress().getAddress();
    }

    public int getServerPort() {
	return acceptor.getLocalAddress().getPort();
    }

    @Override
    public void sessionCreated(IoSession session) {
	LOGGER.info("Delegator:sessionCreated : " + session);
    }

    @Override
    public void sessionClosed(IoSession session) throws Exception {
	LOGGER.info("Delegator:sessionClosed " + session);
	IoSession remoteSession = sessionMap.get(session);
	if (remoteSession == null) {
	    LOGGER.warn("Delegator:sessionClosed : No remote session found mapped to this session.");
	    return;
	}

	remoteSession.close(true);
	sessionMap.remove(session);
    }

    @Override
    public void exceptionCaught(IoSession session, Throwable cause) {
	LOGGER.error("Delegator:exceptionCaught : " + session, cause);
	session.close(true);
    }

    @Override
    public void messageReceived(final IoSession session, Object message) throws Exception {

	if (message instanceof DelegatorMessage) {
	    LOGGER.info("Delegator message received : " + message);
	    handleDelegatorMessage(session, (DelegatorMessage) message);
	} else {
	    IoSession remoteSession = sessionMap.get(session);
	    if (remoteSession == null) {
		LOGGER.error("Delegator:messageReceived : Weird! No session found in map.");
		return;
	    }
	    remoteSession.write(message);
	}
    }

    private void handleDelegatorMessage(final IoSession session, final DelegatorMessage delegatorMessage) {

	switch (delegatorMessage.getCommand()) {
	case CONNECT:
	    handleConnectCommand(session, delegatorMessage);
	    break;
	case UDP_ASSOCIATE:
	    handleUDPAssociateCommand(session, delegatorMessage);
	    break;
	case BIND:
	    break;
	}
    }

    private void handleUDPAssociateCommand(final IoSession session, final DelegatorMessage delegatorMessage) {
	ConnectFuture connectFuture = connectUDP(session, delegatorMessage);
	connectFuture.addListener(new IoFutureListener<ConnectFuture>() {

	    @Override
	    public void operationComplete(ConnectFuture connectFuture) {
		if (connectFuture.isConnected()) {
		    IoSession remoteSession = connectFuture.getSession();
		    sessionMap.put(session, remoteSession);
		    // send acknowledge message
		    InetSocketAddress inetSocketAddress = (InetSocketAddress) remoteSession.getLocalAddress();
		    session.write(new AcknowledgeMessage(inetSocketAddress.getAddress(), inetSocketAddress.getPort()));
		} else {
		    LOGGER.error("Couldn't connect to remote server!");
		    session.close(true);
		}
	    }
	});
    }

    private void handleConnectCommand(final IoSession session, final DelegatorMessage delegatorMessage) {
	HandshakeCompletedListener listener = delegatorMessage.isSSL() ? new HandshakeCompletedListener() {

	    @Override
	    public void handshakeCompleted(HandshakeCompletedEvent event) {
		try {
		    X509Certificate peerCert = event.getPeerCertificateChain()[0];
		    if (certificateMap.containsKey(peerCert.hashCode())) {
			secureSession(session, false, true, certificateMap.get(peerCert.hashCode()));
		    } else {
			SSLContext sslContext = certificateManager.createServerSSLContext(peerCert);
			secureSession(session, false, true, sslContext);
			certificateMap.put(peerCert.hashCode(), sslContext);
		    }
		} catch (Exception ex) {
		    throw new IllegalStateException("Problem occured while securing server connection!", ex);
		}
		// send acknowledge message
		InetSocketAddress inetSocketAddress = (InetSocketAddress) event.getIoSession().getLocalAddress();
		session.write(new AcknowledgeMessage(inetSocketAddress.getAddress(), inetSocketAddress.getPort()));

	    }
	} : null;

	ConnectFuture connectFuture = connectTCP(session, delegatorMessage, listener);
	connectFuture.addListener(new IoFutureListener<ConnectFuture>() {

	    @Override
	    public void operationComplete(ConnectFuture connectFuture) {
		if (connectFuture.isConnected()) {
		    IoSession remoteSession = connectFuture.getSession();
		    sessionMap.put(session, remoteSession);
		    // if it is not SSL, then send ACK immediately.
		    if (!delegatorMessage.isSSL()) {
			// send acknowledge message
			InetSocketAddress inetSocketAddress = (InetSocketAddress) remoteSession.getLocalAddress();
			session.write(new AcknowledgeMessage(inetSocketAddress.getAddress(), inetSocketAddress.getPort()));
		    }
		} else {
		    LOGGER.error("Couldn't connect to remote server!");
		    session.close(true);
		}
	    }
	});
    }

    private void secureSession(IoSession session, boolean isClient, boolean disableEncOnce, SSLContext context) {

	SslFilter sslfilter = new SslFilter(context);
	sslfilter.setUseClientMode(isClient);
	session.getFilterChain().addFirst(SSLFILTER, sslfilter);
	if (disableEncOnce) {
	    session.setAttribute(SslFilter.DISABLE_ENCRYPTION_ONCE);
	}
    }

    private ConnectFuture connectTCP(IoSession session, DelegatorMessage msg, HandshakeCompletedListener listener) {
	NioSocketConnector connector = new NioSocketConnector(this.ioProcessor);
	connector.setHandler(new ClientProtocolHandler(session, listener));
	if (msg.isSSL()) {
	    SslFilter sslfilter = new SslFilter(certificateManager.getClientSSLContext());
	    sslfilter.setUseClientMode(true);
	    connector.getFilterChain().addFirst(SSLFILTER, sslfilter);
	}
	return connector.connect(new InetSocketAddress(msg.getAddress(), msg.getPort()));
    }

    private ConnectFuture connectUDP(IoSession session, DelegatorMessage msg) {
	NioDatagramConnector connector = new NioDatagramConnector(this.ioProcessor);
	connector.setHandler(new ClientProtocolHandler(session, null));
	return connector.connect(new InetSocketAddress(msg.getAddress(), msg.getPort()));
    }
}

class ClientProtocolHandler extends AbstractIoHandler {

    private static Logger LOGGER = LoggerFactory.getLogger(ClientProtocolHandler.class);

    private final IoSession sourceSession;
    private HandshakeCompletedListener listener;
    private PrintStream filePrintStream;
    private HexDumpEncoder hexDumpEncoder = new HexDumpEncoder();

    public ClientProtocolHandler(IoSession sourceSession, HandshakeCompletedListener listener) {
	this.sourceSession = sourceSession;
	this.listener = listener;
    }

    @Override
    public void sessionCreated(IoSession session) {
	LOGGER.info("Session created! " + session);
	session.getConfig().setUseReadOperation(true);
	session.setAttribute(SslFilter.USE_NOTIFICATION, Boolean.TRUE);
	String fileName = sourceSession.getRemoteAddress() + "___" + session.getRemoteAddress() + "_@" + session.hashCode();
	fileName = fileName.replace("/", "").replace(':', '-');
	try {
	    filePrintStream = new PrintStream(fileName);
	} catch (FileNotFoundException e) {
	    e.printStackTrace();
	}
    }

    @Override
    public void sessionClosed(IoSession session) throws Exception {
	LOGGER.info("Session closed! " + session);
	filePrintStream.close();
    }

    @Override
    public void exceptionCaught(IoSession session, Throwable cause) {
	LOGGER.error("Exception caught! " + session, cause);
	filePrintStream.close();
	session.close(false);
    }

    @Override
    public void messageReceived(IoSession session, Object message) throws Exception {

	if (message == SslFilter.SESSION_UNSECURED) {
	    return;// ignore
	}

	if (message == SslFilter.SESSION_SECURED) {
	    if (listener != null) {
		SslFilter sslFilter = (SslFilter) session.getFilterChain().get(SslFilter.class);
		listener.handshakeCompleted(new HandshakeCompletedEvent(session, sslFilter.getSslSession(session)));
	    }
	    return;
	}

	filePrintStream.println("\nRECEIVED:");
	IoBuffer ioBuffer = (IoBuffer) message;
	ioBuffer.mark();
	hexDumpEncoder.encode(ioBuffer.buf(), filePrintStream);
	ioBuffer.reset();
	sourceSession.write(message);
    }

    @Override
    public void messageSent(IoSession session, Object message) throws Exception {
	filePrintStream.println("SENT:");
	IoBuffer ioBuffer = (IoBuffer) message;
	ioBuffer.mark();
	hexDumpEncoder.encode(ioBuffer.buf(), filePrintStream);
	ioBuffer.reset();
    }
}
