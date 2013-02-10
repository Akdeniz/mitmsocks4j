package com.akdeniz.mitmsocks4j.protocol.types;
/**
 * 
 * @author akdeniz
 *
 */
public enum Command {
    CONNECT((byte) 1), BIND((byte) 2), UDP_ASSOCIATE((byte) 3), NOT_SUPPORTED((byte) 0xFF);

    public byte value;

    Command(byte value) {
	this.value = value;
    }

    public static Command valueOf(byte value) {
	for (Command command : values()) {
	    if (command.value == value)
		return command;
	}
	return NOT_SUPPORTED;
    }
}
