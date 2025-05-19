package org.tinyradius.packet;

/**
 * CoA packet. Thanks to Michael Krastev.
 *
 * @author Michael Krastev <mkrastev@gmail.com>
 */
public class CoaRequest extends RadiusPacket {

    public CoaRequest() {
        this(COA_REQUEST);
    }

    public CoaRequest(final int type) {
        super(type, getNextPacketIdentifier());
    }

    /**
     * @see AccountingRequest#updateRequestAuthenticator(String, int, byte[])
     */
    @Override
    protected byte[] updateRequestAuthenticator(String sharedSecret, int packetLength, byte[] attributes) {
        return updateReqAuthenticator(sharedSecret, packetLength, attributes);

    }

}
