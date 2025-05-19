/**
 * $Id: RadiusClient.java,v 1.7 2005/11/10 10:20:21 wuttke Exp $
 * Created on 09.04.2005
 *
 * @author Matthias Wuttke
 * @version $Revision: 1.7 $
 */
package org.tinyradius.util;

import java.io.*;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.security.NoSuchAlgorithmException;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.tinyradius.packet.RadiusPacket;

/**
 * This object represents a simple Radius client which communicates with a
 * specified Radius server. You can use a single instance of this object to
 * authenticate or account different users with the same Radius server as long
 * as you authenticate/account one user after the other. This object is thread
 * safe, but only opens a single socket so operations using this socket are
 * synchronized to avoid confusion with the mapping of request and result
 * packets.
 */
public class RadSecRadiusClient extends RadiusClient {

    /**
     * Creates a new Radius client object for a special Radius server.
     *
     * @param hostName host name of the Radius server
     * @param sharedSecret shared secret used to secure the communication
     * @param sslContext
     */
    public RadSecRadiusClient(String hostName, String sharedSecret, SSLContext sslContext) {
        super(hostName, sharedSecret);
        setSSLContext(sslContext);
    }

    public RadSecRadiusClient(String hostName, String sharedSecret) {
        this(hostName, sharedSecret, null);
    }

    /**
     * Constructs a Radius client for the given Radius endpoint.
     *
     * @param client Radius endpoint
     */
    public RadSecRadiusClient(RadiusEndpoint client) {
        this(client.getEndpointAddress().getAddress().getHostAddress(), client.getSharedSecret());
    }

    /**
     * Closes the socket of this client.
     *
     * @throws java.io.IOException
     */
    @Override
    public void close() {
        if (serverSocket != null) {
            try {
                serverSocket.close();
            } catch (IOException e) {
                logger.error("Closing socket failure", e);
            }

        }
        serverSocket = null;
        sslContext = null;
        socketFactory = null;
    }

    public void setSSLContext(SSLContext sslContext) {
        if (sslContext == null) {

            try {
                sslContext = SSLContext.getDefault();

            } catch (NoSuchAlgorithmException e) {
                logger.error("Settings SSL Context failure", e);
                return;
            }
        }

        this.sslContext = sslContext;
        socketFactory = this.sslContext.getSocketFactory();
    }

    /**
     * Sets the socket timeout
     *
     * @param socketTimeout timeout, ms, >0
     * @throws SocketException
     */
    @Override
    public void setSocketTimeout(int socketTimeout) throws SocketException {
        if (socketTimeout < 1) {
            throw new IllegalArgumentException("socket tiemout must be positive");
        }
        super.setSocketTimeout(socketTimeout);
        if (serverSocket != null) {
            serverSocket.setSoTimeout(socketTimeout);
        }
    }

    /**
     * Sends a Radius packet to the server and awaits an answer.
     *
     * @param request packet to be sent
     * @param port server port number
     * @return response Radius packet
     * @exception RadiusException malformed packet
     * @exception IOException communication error (after getRetryCount()
     * retries)
     */
    @Override
    public RadiusPacket communicate(RadiusPacket request, int port) throws IOException, RadiusException {
        byte[] packetIn = null;
        byte[] packetOut = makeBytePacket(request);
        InputStream in = null;
        OutputStream out = null;

        try {

            SSLSocket socket = getSocket(port);
            in = socket.getInputStream();
            out = socket.getOutputStream();

            for (int i = 1; i <= getRetryCount(); i++) {
                try {
                    send(out, packetOut);
                    packetIn = receive(in);
                    return makeRadiusPacket(packetIn, request);
                } catch (IOException ioex) {
                    if (i == getRetryCount()) {
                        if (logger.isErrorEnabled()) {
                            if (ioex instanceof SocketTimeoutException) {
                                logger.error("communication failure (timeout), no more retries");
                            } else {
                                logger.error("communication failure, no more retries", ioex);
                            }
                        }
                        throw ioex;
                    }
                    if (logger.isInfoEnabled()) {
                        logger.info("communication failure, retry " + i);
                    }
                    // TODO increase Acct-Delay-Time by getSocketTimeout()/1000
                    // this changes the packet authenticator and requires packetOut to be
                    // calculated again (call makeDatagramPacket)
                }
            }
        } finally {
            if (in != null) {
                in.close();
            }
            if (out != null) {
                out.close();
            }

        }

        return null;
    }

    /**
     * Sends the specified packet to the specified Radius server endpoint.
     *
     * @param remoteServer Radius endpoint consisting of server address, port
     * number and shared secret
     * @param request Radius packet to be sent
     * @return received response packet
     * @throws RadiusException malformed packet
     * @throws IOException error while communication
     */
    public static RadiusPacket communicate(RadiusEndpoint remoteServer, RadiusPacket request) throws RadiusException, IOException {
        RadSecRadiusClient rc = new RadSecRadiusClient(remoteServer);
        return rc.communicate(request, remoteServer.getEndpointAddress().getPort());
    }

    /**
     * Returns the socket used for the server communication.It is bound to an
     * arbitrary free local port number.
     *
     * @param port
     * @return local socket
     * @throws SocketException
     * @throws java.net.UnknownHostException
     */
    private SSLSocket getSocket(int port) throws SocketException, UnknownHostException, IOException {
        if (serverSocket == null) {
            serverSocket = (SSLSocket) socketFactory.createSocket(InetAddress.getByName(getHostName()), port);
            serverSocket.setReuseAddress(true);
            serverSocket.setSoTimeout(getSocketTimeout());
        }
        return serverSocket;
    }

    private byte[] makeBytePacket(RadiusPacket packet) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        packet.encodeRequestPacket(bos, getSharedSecret());
        byte[] data = bos.toByteArray();

        return data;
    }

    /**
     * Creates a RadiusPacket from a received datagram packet.
     *
     * @param packet received datagram
     * @param request Radius request packet
     * @return RadiusPacket object
     */
    private RadiusPacket makeRadiusPacket(byte[] packet, RadiusPacket request) throws IOException, RadiusException {
        ByteArrayInputStream in = new ByteArrayInputStream(packet);
        return RadiusPacket.decodeResponsePacket(in, getSharedSecret(), request);
    }

    private void send(OutputStream out, byte[] data) throws IOException {

        if (out == null) {
            return;
        }

        synchronized (out) {
            out.write(data);
            out.flush();
        }

    }

    private byte[] receive(InputStream in) throws IOException {

        byte[] data = new byte[RadiusPacket.MAX_PACKET_LENGTH];

        if (in == null) {
            return data;
        }

        synchronized (in) {
            int l = in.read(data);
        }
        return data;
    }

    private SSLContext sslContext = null;
    private SSLSocketFactory socketFactory = null;
    private SSLSocket serverSocket;
    private static Logger logger = LoggerFactory.getLogger(RadSecRadiusClient.class);

}
