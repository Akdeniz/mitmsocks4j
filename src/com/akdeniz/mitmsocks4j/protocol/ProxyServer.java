package com.akdeniz.mitmsocks4j.protocol;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.mina.core.future.ConnectFuture;
import org.apache.mina.core.future.IoFutureListener;
import org.apache.mina.core.service.SimpleIoProcessorPool;
import org.apache.mina.core.session.IoSession;
import org.apache.mina.filter.codec.ProtocolCodecFilter;
import org.apache.mina.transport.socket.SocketAcceptor;
import org.apache.mina.transport.socket.nio.NioProcessor;
import org.apache.mina.transport.socket.nio.NioSession;
import org.apache.mina.transport.socket.nio.NioSocketAcceptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.akdeniz.mitmsocks4j.mina.protocol.SOCKSCodecFactory;
import com.akdeniz.mitmsocks4j.protocol.messages.ClientHello;
import com.akdeniz.mitmsocks4j.protocol.messages.ClientRequest;
import com.akdeniz.mitmsocks4j.protocol.messages.ServerHello;
import com.akdeniz.mitmsocks4j.protocol.messages.ServerReply;
import com.akdeniz.mitmsocks4j.protocol.mitm.AcknowledgeMessage;
import com.akdeniz.mitmsocks4j.protocol.mitm.DelegatorMessage;
import com.akdeniz.mitmsocks4j.protocol.types.AuthenticationMethod;
import com.akdeniz.mitmsocks4j.protocol.types.Command;
import com.akdeniz.mitmsocks4j.protocol.types.ReplyCode;
import com.akdeniz.mitmsocks4j.protocol.types.SocksVersion;

/**
 * Handles SOCKS proxy protocol and directs data to {@link Delegator}.
 * 
 * @author akdeniz
 *
 */
public class ProxyServer extends AbstractIoHandler {

    public static Logger LOGGER = LoggerFactory.getLogger(ProxyServer.class);

    public static final SimpleIoProcessorPool<NioSession> IO_PROCESSOR_POOL = new SimpleIoProcessorPool<>(NioProcessor.class);

    private final Map<IoSession, IoSession> sessionMap = new ConcurrentHashMap<IoSession, IoSession>(3);

    private SocketAcceptor acceptor;
    private Delegator delegator;

    private final int proxyPort;

    private final int delegatorPort;

    private final List<Integer> securedPorts;

    private CertificateManager certificateManager;

    public ProxyServer(int proxyPort, int delegatorPort, List<Integer> securedPorts, String keystorePath, char[] password) throws Exception {
	this.proxyPort = proxyPort;
	this.delegatorPort = delegatorPort;
	this.securedPorts = securedPorts;
	
	certificateManager = new CertificateManager(keystorePath, password);

	acceptor = new NioSocketAcceptor(IO_PROCESSOR_POOL);
	acceptor.getFilterChain().addLast("codec", new ProtocolCodecFilter(new SOCKSCodecFactory()));
	acceptor.setReuseAddress(true);
	acceptor.setHandler(this);
	delegator = new Delegator(IO_PROCESSOR_POOL, certificateManager);
    }

    public void start() throws IOException {
	acceptor.bind(new InetSocketAddress(proxyPort));
	delegator.start(delegatorPort);
    }

    @Override
    public void sessionCreated(IoSession session) throws Exception {
	LOGGER.info("Session created! : " + session);
    }

    @Override
    public void sessionClosed(IoSession session) throws Exception {
	IoSession remoteSession = sessionMap.get(session);
	if (remoteSession == null) {
	    LOGGER.warn("Delegator:sessionClosed : No remote session found mapped to this session.");
	    return;
	}

	remoteSession.close(true);
	sessionMap.remove(session);
    }

    @Override
    public void exceptionCaught(IoSession session, Throwable cause) throws Exception {
	LOGGER.error("ProxyServerMINA:exceptionCaught : " + session, cause);
	session.close(true);
    }

    @Override
    public void messageReceived(final IoSession session, Object message) throws Exception {
	if (message instanceof ClientHello) {
	    ClientHello hello = (ClientHello) message;
	    LOGGER.info(hello.toString());
	    if (hello.version == SocksVersion.SOCKSv5) {
		if (hello.methods.contains(AuthenticationMethod.NOAUTH)) {
		    session.write(new ServerHello(SocksVersion.SOCKSv5, AuthenticationMethod.NOAUTH));
		} else {
		    LOGGER.warn("Unacceptable SOCKS authentication! Rejecting connection..");
		    session.write(new ServerHello(SocksVersion.SOCKSv5, AuthenticationMethod.NO_ACCEPTABLE_METHODS));
		}
	    } else {
		LOGGER.error("Unacceptable SOCKS version! Rejecting connection..");
		session.close(true);
	    }
	} else if (message instanceof ClientRequest) {
	    ClientRequest clientRequest = (ClientRequest) message;
	    LOGGER.info(clientRequest.toString());
	    switch (clientRequest.command) {
	    case CONNECT:
		doConnect(session, clientRequest);
		break;
	    case BIND:
		doBind(session);
		break;
	    case UDP_ASSOCIATE:
		doUDPAssociate(session, clientRequest);
		break;
	    case NOT_SUPPORTED:
		session.write(new ServerReply(SocksVersion.SOCKSv5, ReplyCode.COMMAND_NOT_SUPPORTED, null, (short) 0));
		break;
	    }
	} else {
	    IoSession remoteSession = sessionMap.get(session);
	    if (remoteSession == null) {
		LOGGER.error("ProxyServerMINA:messageReceived : Weird! No session found in map.");
		return;
	    }
	    remoteSession.write(message);
	}
    }

    private void doUDPAssociate(final IoSession session, final ClientRequest clientRequest) {
	ConnectFuture connectFuture = delegator.newSession(new PipeHandler(session));
	connectFuture.addListener(new IoFutureListener<ConnectFuture>() {
	    @Override
	    public void operationComplete(ConnectFuture connectFuture) {
		if (connectFuture.isConnected()) {
		    IoSession remoteSession = connectFuture.getSession();
		    sessionMap.put(session, remoteSession);
		    DelegatorMessage connectMessage = new DelegatorMessage(Command.UDP_ASSOCIATE, clientRequest.destAddress, clientRequest.destPort, false);
		    remoteSession.write(connectMessage);
		} else { // XXX this failure is belongs to connection to delegator,
			 // not to actual server. So this message may not be
			 // appropriate!
		    LOGGER.error("ProxyServerMINA:messageReceived : Couldn't connect to remote server!");
		    session.write(new ServerReply(SocksVersion.SOCKSv5, ReplyCode.CONNECTION_REFUSED, null, (short) 0));
		}
	    }
	});
    }

    private void doBind(IoSession session) {
	throw new IllegalStateException("BIND command is not currently supported!");
    }

    private void doConnect(final IoSession session, final ClientRequest clientRequest) {
	ConnectFuture connectFuture = delegator.newSession(new PipeHandler(session));
	connectFuture.addListener(new IoFutureListener<ConnectFuture>() {
	    @Override
	    public void operationComplete(ConnectFuture connectFuture) {
		if (connectFuture.isConnected()) {
		    IoSession remoteSession = connectFuture.getSession();
		    sessionMap.put(session, remoteSession);
		    DelegatorMessage connectMessage = new DelegatorMessage(Command.CONNECT, clientRequest.destAddress, clientRequest.destPort, securedPorts
			    .contains(new Integer(clientRequest.destPort)));
		    remoteSession.write(connectMessage);
		} else { // XXX this failure is belongs to connection to delegator,
			 // not to actual server. So this message may not be
			 // appropriate!
		    LOGGER.error("Couldn't connect to remote server!");
		    session.write(new ServerReply(SocksVersion.SOCKSv5, ReplyCode.CONNECTION_REFUSED, null, (short) 0));
		}
	    }
	});
    }
}

/**
 * Data piper between {@link Delegator} and proxy client.
 * @author akdeniz
 *
 */
class PipeHandler extends AbstractIoHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(PipeHandler.class);
    private IoSession sourceSession;

    public PipeHandler(IoSession sourceSession) {
	this.sourceSession = sourceSession;
    }

    @Override
    public void sessionCreated(IoSession session) throws Exception {
	LOGGER.info("PipeHandler:sessionCreated " + session);
    }

    @Override
    public void sessionClosed(IoSession session) throws Exception {
	sourceSession.close(true);
    }

    @Override
    public void exceptionCaught(IoSession session, Throwable cause) throws Exception {
	LOGGER.error("PipeHandler:exceptionCaught " + session + " --- " + cause.getMessage());
	session.close(true);
    }

    @Override
    public void messageReceived(IoSession session, Object message) throws Exception {
	LOGGER.info(session + " : " + message);
	if (message instanceof AcknowledgeMessage) {
	    // TODO: we may use ack message for some purpose!!
	    AcknowledgeMessage ackMessage = (AcknowledgeMessage) message;
	    InetSocketAddress localAddress = (InetSocketAddress) sourceSession.getLocalAddress();
	    sourceSession.write(new ServerReply(SocksVersion.SOCKSv5, ReplyCode.SUCCESS, localAddress.getAddress(), (short) localAddress.getPort()));
	} else {
	    sourceSession.write(message);
	}
    }

    @Override
    public void messageSent(IoSession session, Object message) throws Exception {
	LOGGER.info(session + " : " + message);
    }
}
