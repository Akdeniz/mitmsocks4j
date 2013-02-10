package com.akdeniz.mitmsocks4j.protocol.messages;

/**
 * Interface of server response packets.
 * 
 * @author akdeniz
 *
 */
public interface Encodable {

    byte[] getEncoded();
}
