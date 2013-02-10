package com.akdeniz.mitmsocks4j.mina.protocol;

import org.apache.mina.core.buffer.IoBuffer;
import org.apache.mina.core.session.IoSession;
import org.apache.mina.filter.codec.CumulativeProtocolDecoder;
import org.apache.mina.filter.codec.ProtocolCodecFactory;
import org.apache.mina.filter.codec.ProtocolDecoder;
import org.apache.mina.filter.codec.ProtocolDecoderOutput;
import org.apache.mina.filter.codec.ProtocolEncoder;

import com.akdeniz.mitmsocks4j.protocol.mitm.AcknowledgeMessage;

/**
 * Protocol codec factory for Delegator.
 * 
 * @author akdeniz
 *
 */
public class DelegatorLocalCodecFactory implements ProtocolCodecFactory {

    private ProtocolEncoder protocolEncoder;
    private ProtocolDecoder protocolDecoder;

    public DelegatorLocalCodecFactory() {
	protocolEncoder = new MessageProtocolEncoder();
	protocolDecoder = new DelegatorLocalRequestDecoder();
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

class DelegatorLocalRequestDecoder extends CumulativeProtocolDecoder {

    private static final String DECODER_STATE_KEY = DelegatorLocalRequestDecoder.class.getName() + ".STATE";

    enum STATE {
	ACK, DATA
    }

    @Override
    protected boolean doDecode(IoSession session, IoBuffer in, ProtocolDecoderOutput out) throws Exception {

	STATE state = (STATE) session.getAttribute(DECODER_STATE_KEY, STATE.ACK);

	switch (state) {
	case ACK:
	    AcknowledgeMessage ackMessage = new AcknowledgeMessage();
	    if (ackMessage.decode(in)) {
		out.write(ackMessage);
		session.setAttribute(DECODER_STATE_KEY, STATE.DATA);
		return true;
	    } else {
		return false;
	    }
	case DATA:
	    // copy data // XXX fair? If we ensure that end-receiver would
	    // consume all buffer, we can send buffer as it is...
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