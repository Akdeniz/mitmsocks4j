package com.akdeniz.mitmsocks4j.mina.protocol;

import org.apache.mina.core.buffer.IoBuffer;
import org.apache.mina.core.session.IoSession;
import org.apache.mina.filter.codec.CumulativeProtocolDecoder;
import org.apache.mina.filter.codec.ProtocolCodecFactory;
import org.apache.mina.filter.codec.ProtocolDecoder;
import org.apache.mina.filter.codec.ProtocolDecoderOutput;
import org.apache.mina.filter.codec.ProtocolEncoder;

import com.akdeniz.mitmsocks4j.protocol.mitm.DelegatorMessage;

public class DelegatorRemoteCodecFactory implements ProtocolCodecFactory {

    private ProtocolEncoder protocolEncoder;
    private ProtocolDecoder protocolDecoder;

    public DelegatorRemoteCodecFactory() {
	protocolDecoder = new DelegatorRemoteRequestDecoder();
	protocolEncoder = new MessageProtocolEncoder();
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

class DelegatorRemoteRequestDecoder extends CumulativeProtocolDecoder {

    private static final String DECODER_STATE_KEY = DelegatorRemoteRequestDecoder.class.getName() + ".STATE";

    enum STATE {
	CONNECT, DATA
    }

    @Override
    protected boolean doDecode(IoSession session, IoBuffer in, ProtocolDecoderOutput out) throws Exception {

	STATE state = (STATE) session.getAttribute(DECODER_STATE_KEY, STATE.CONNECT);

	switch (state) {
	case CONNECT:
	    DelegatorMessage connectMessage = new DelegatorMessage();
	    if (connectMessage.decode(in)) {
		out.write(connectMessage);
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