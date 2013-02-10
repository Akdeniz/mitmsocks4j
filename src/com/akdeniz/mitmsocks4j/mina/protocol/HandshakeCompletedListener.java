package com.akdeniz.mitmsocks4j.mina.protocol;

/**
 * 
 * @author akdeniz
 *
 */
public abstract interface HandshakeCompletedListener
{
  public abstract void handshakeCompleted(HandshakeCompletedEvent paramHandshakeCompletedEvent);
}