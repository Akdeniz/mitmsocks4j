package com.akdeniz.mitmsocks4j.mina.protocol;

import org.apache.mina.core.buffer.IoBuffer;
import org.apache.mina.core.session.IoSession;
import org.apache.mina.filter.codec.ProtocolEncoder;
import org.apache.mina.filter.codec.ProtocolEncoderOutput;

import com.akdeniz.mitmsocks4j.protocol.messages.Encodable;

/**
 * 
 * @author akdeniz
 *
 */
public class MessageProtocolEncoder implements ProtocolEncoder {

    @Override
    public void encode(IoSession session, Object message, ProtocolEncoderOutput out) throws Exception {

	if (message instanceof Encodable) {
	    Encodable encodable = (Encodable) message;
	    out.write(IoBuffer.wrap(encodable.getEncoded()));
	} else {
	    out.write(message);
	}
    }

    @Override
    public void dispose(IoSession session) throws Exception {
    }
}