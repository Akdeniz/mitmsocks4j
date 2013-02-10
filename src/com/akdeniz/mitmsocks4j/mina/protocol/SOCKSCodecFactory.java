package com.akdeniz.mitmsocks4j.mina.protocol;

import org.apache.mina.core.buffer.IoBuffer;
import org.apache.mina.core.session.IoSession;
import org.apache.mina.filter.codec.CumulativeProtocolDecoder;
import org.apache.mina.filter.codec.ProtocolCodecFactory;
import org.apache.mina.filter.codec.ProtocolDecoder;
import org.apache.mina.filter.codec.ProtocolDecoderOutput;
import org.apache.mina.filter.codec.ProtocolEncoder;

import com.akdeniz.mitmsocks4j.protocol.messages.ClientHello;
import com.akdeniz.mitmsocks4j.protocol.messages.ClientRequest;

/**
 * Protocol codec factory for Proxy listener.
 * 
 * @author akdeniz
 *
 */
public class SOCKSCodecFactory implements ProtocolCodecFactory {

    private ProtocolEncoder protocolEncoder;
    private ProtocolDecoder protocolDecoder;

    public SOCKSCodecFactory() {
	protocolEncoder = new MessageProtocolEncoder();
	protocolDecoder = new SOCKSRequestDecoder();
    }

    @Override
    public ProtocolEncoder getEncoder(IoSession session) throws Exception {
	return protocolEncoder;
    }

    @Override
    public ProtocolDecoder getDecoder(IoSession session) throws Exception {
	return protocolDecoder;
    }

}

class SOCKSRequestDecoder extends CumulativeProtocolDecoder {

    private static final String DECODER_STATE_KEY = SOCKSRequestDecoder.class.getName() + ".STATE";

    enum STATE {
	AUTH, REQUEST, DATA
    }

    @Override
    protected boolean doDecode(IoSession session, IoBuffer in, ProtocolDecoderOutput out) throws Exception {

	STATE state = (STATE) session.getAttribute(DECODER_STATE_KEY, STATE.AUTH);

	switch (state) {
	case AUTH:
	    ClientHello clientHello = new ClientHello();
	    if (clientHello.decode(in)) {
		out.write(clientHello);
		session.setAttribute(DECODER_STATE_KEY, STATE.REQUEST);
		return true;
	    } else {
		return false;
	    }
	case REQUEST:
	    ClientRequest request = new ClientRequest();
	    if (request.decode(in)) {
		out.write(request);
		session.setAttribute(DECODER_STATE_KEY, STATE.DATA);
		return true;
	    } else {
		return false;
	    }
	case DATA:
	    // XXX : is copying data fair? If we ensure that end-receiver would consume all buffer,
	    // we can send buffer as it is...
	    IoBuffer buffer = IoBuffer.allocate(in.remaining());
	    buffer.put(in);
	    buffer.flip();
	    out.write(buffer);
	    return true;
	default:
	    return false;
	}
    }
}
