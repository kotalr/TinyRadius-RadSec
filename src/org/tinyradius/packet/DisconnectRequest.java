package org.tinyradius.packet;

public class DisconnectRequest extends RadiusPacket {

    public DisconnectRequest() {
        this(DISCONNECT_REQUEST);
    }

    public DisconnectRequest(final int type) {
        super(type, getNextPacketIdentifier());
    }

    /**
     * @see AccountingRequest#updateRequestAuthenticator(String, int, byte[])
     */
    @Override
    protected byte[] updateRequestAuthenticator(String sharedSecret, int packetLength, byte[] attributes) {
        return updateReqAuthenticator( sharedSecret,  packetLength, attributes);
    }

}
