/**
 * $Id: RadiusServer.java,v 1.11 2008/04/24 05:22:50 wuttke Exp $
 * Created on 09.04.2005
 *
 * @author Matthias Wuttke
 * @version $Revision: 1.11 $
 */
package org.tinyradius.util;

import java.io.*;
import java.net.*;
import java.security.NoSuchAlgorithmException;
import javax.net.ServerSocketFactory;
import javax.net.ssl.SSLContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.tinyradius.packet.RadiusPacket;

/**
 * Implements a simple Radius server. This class must be subclassed to provide
 * an implementation for getSharedSecret() and getUserPassword(). If the server
 * supports accounting, it must override accountingRequestReceived().
 */
public abstract class RadSecRadiusServer extends RadiusServer implements AbstractRadiusServer {

    /**
     * Starts the Radius server.
     *
     * @param listenAuth open auth port?
     * @param listenAcct open acct port?
     */
    @Override
    public void start(boolean listenAuth, boolean listenAcct) {
        if (listenAuth) {
            new Thread() {
                @Override
                public void run() {
                    setName("Radius Auth Listener");
                    try {
                        logger.info("starting RadiusAuthListener for Client " + getRadiusClient() + " on port " + getAuthPort());
                        listen(getAuthServerSocket());
                        logger.info("RadiusAuthListener is being terminated");
                    } catch (IOException e) {
                        e.printStackTrace();
                        logger.error("auth thread stopped by exception", e);
                    } finally {
                        try {
                            authSocket.close();
                        } catch (IOException ex) {
                            ex.printStackTrace();
                            logger.error("auth thread stopped by exception", ex);
                        }
                        logger.debug("auth socket closed");
                    }
                }
            }.start();
        }

        if (listenAcct) {
            new Thread() {
                @Override
                public void run() {
                    setName("Radius Acct Listener");
                    try {
                        logger.info("starting RadiusAcctListener for Client " + getRadiusClient() + " on port " + getAcctPort());
                        listen(getAcctServerSocket());
                        logger.info("RadiusAcctListener is being terminated");
                    } catch (IOException e) {
                        e.printStackTrace();
                        logger.error("acct thread stopped by exception", e);
                    } finally {
                        try {
                            acctSocket.close();
                        } catch (IOException ex) {
                            ex.printStackTrace();
                            logger.error("auth thread stopped by exception", ex);
                        }
                        logger.debug("acct socket closed");
                    }
                }
            }.start();
        }
    }

    /**
     * Stops the server and closes the sockets.
     */
    @Override
    public void stop() {
        logger.info("stopping Radius server");
        closing = true;

        if (getExecutor() != null) {
            getExecutor().shutdown();
        }
        if (authSocket != null) {
            try {
                authSocket.close();
            } catch (IOException e) {
                e.printStackTrace();
                logger.error("auth stopped by exception", e);
            }
        }
        if (acctSocket != null) {
            try {
                acctSocket.close();
            } catch (IOException e) {
                e.printStackTrace();
                logger.error("acct stopped by exception", e);
            }
        }
        sslContext = null;
        socketFactory = null;
        authSocket = null;
        acctSocket = null;
    }

    /**
     * Sets the socket timeout.
     *
     * @param socketTimeout socket timeout, >0 ms
     * @throws SocketException
     */
    @Override
    public void setSocketTimeout(int socketTimeout) throws SocketException {
        if (socketTimeout < 1) {
            throw new IllegalArgumentException("socket tiemout must be positive");
        }
        super.setSocketTimeout(socketTimeout);
        if (authSocket != null) {
            authSocket.setSoTimeout(socketTimeout);
        }
        if (acctSocket != null) {
            acctSocket.setSoTimeout(socketTimeout);
        }
    }

    @Override
    public void setSSLContext(SSLContext sslContext) throws NoSuchAlgorithmException {
        if (sslContext == null) {
            sslContext = SSLContext.getDefault();
        }
        this.sslContext = sslContext;
        socketFactory = sslContext.getServerSocketFactory();

    }

    public void setBacklog(int backlog) {
        this.backlog = backlog;
    }

    //////////////////////////////////////////////////////////////////////////////





    /**
     * Listens on the passed socket, blocks until stop() is called.
     *
     * @param s socket to listen on
     */
    private void listen(final ServerSocket s) {

        while (closing == false) {
            try {
                Socket socket = s.accept();
                if (getExecutor() == null) {
                    processRequest(socket);
                } else {
                    getExecutor().submit(new Runnable() {
                        @Override
                        public void run() {
                            try {
                                processRequest(socket);
                            } catch (IOException e) {
                                e.printStackTrace();
                                logger.error("processRequest crashed by exception", e);
                            }
                        }

                    });
                }
            } catch (Exception e) {
                // error while reading/writing socket
                if (e instanceof SocketTimeoutException) {
                    logger.trace("normal socket timeout");
                } else {
                    if (closing == false) {
                        logger.error("communication error", e);
                    }
                }
                if (closing) {
                    break;
                }
            }
        }
        logger.info("got closing signal - end listen thread");
    }

    private byte[] receive(InputStream in) throws IOException {

        byte[] data = new byte[RadiusPacket.MAX_PACKET_LENGTH];
        int len = 0;

        if (in == null) {
            return data;
        }

        len = in.read(data);

        return data;
    }

    private void send(OutputStream out, byte[] data) throws IOException {

        if (out == null) {
            return;
        }

        out.write(data);
        out.flush();
    }

    /**
     * Process a single received request
     *
     * @param socket
     * @throws java.io.IOException
     */
    private void processRequest(Socket socket) throws IOException {
        byte[] packetIn = null;
        InputStream in = null;
        OutputStream out = null;

        try {

            // check client
            final InetSocketAddress localAddress = new InetSocketAddress(socket.getLocalAddress(), socket.getLocalPort());
            final InetSocketAddress remoteAddress = new InetSocketAddress(socket.getInetAddress(), socket.getPort());
            String secret = getSharedSecret(remoteAddress, getRadiusClient(), getRadiusSecret());

            if (secret == null) {
                if (logger.isInfoEnabled()) {
                    logger.info("ignoring packet from unknown client " + remoteAddress + " received on local address " + localAddress);
                }
                return;
            }

            in = socket.getInputStream();
            out = socket.getOutputStream();

            //receive data
            packetIn = receive(in);

            // parse packet
            final RadiusPacket request = makeRadiusPacket(packetIn, secret, RadiusPacket.UNDEFINED);
            if (logger.isInfoEnabled()) {
                logger.info("received packet from " + remoteAddress + " on local address " + localAddress + ": " + request);
            }

            // handle packet
            logger.trace("about to call RadiusServer.handlePacket()");
            final RadiusPacket response = handlePacket(localAddress, remoteAddress, request, secret);

            // send response
            if (response != null) {
                if (logger.isInfoEnabled()) {
                    logger.info("send response: " + response);
                }
                byte[] packetOut = makeBytePacket(response, secret, request);
                send(out, packetOut);
            } else {
                logger.info("no response sent");
            }
        } catch (IOException ioe) {
            // error while reading/writing socket
            logger.error("communication error", ioe);
        } catch (RadiusException re) {
            // malformed packet
            logger.error("malformed Radius packet", re);
        } finally {
            if (in != null) {
                in.close();
            }
            if (out != null) {
                out.close();
            }
            if (socket != null) {
                socket.close();
            }
        }
    }

    /**
     * Returns a socket bound to the auth port.
     *
     * @return socket
     * @throws SocketException
     */
    private ServerSocket getAuthServerSocket() throws SocketException, IOException {
        if (authSocket == null) {

            if (getListenAddress() == null) {
                if (socketFactory != null) {
                    authSocket = socketFactory.createServerSocket(getAuthPort(), backlog);
                } else {
                    authSocket = new ServerSocket(getAuthPort(), backlog);
                }
            } else {
                if (socketFactory != null) {
                    authSocket = socketFactory.createServerSocket(getAuthPort(), backlog, getListenAddress());
                } else {
                    authSocket = new ServerSocket(getAuthPort(), backlog, getListenAddress());
                }

            }
            authSocket.setSoTimeout(getSocketTimeout());
            authSocket.setReuseAddress(true);
        }
        return authSocket;
    }

    /**
     * Returns a socket bound to the acct port.
     *
     * @return socket
     * @throws SocketException
     */
    private ServerSocket getAcctServerSocket() throws SocketException, IOException {
        if (acctSocket == null) {

            if (getListenAddress() == null) {
                if (socketFactory != null) {
                    acctSocket = socketFactory.createServerSocket(getAcctPort(), backlog);
                } else {
                    acctSocket = new ServerSocket(getAcctPort(), backlog);
                }
            } else {
                if (socketFactory != null) {
                    acctSocket = socketFactory.createServerSocket(getAcctPort(), backlog, getListenAddress());
                } else {
                    acctSocket = new ServerSocket(getAcctPort(), backlog, getListenAddress());
                }

            }

            acctSocket.setSoTimeout(getSocketTimeout());
            acctSocket.setReuseAddress(true);
        }
        return acctSocket;
    }

    /**
     * Creates a Radius response datagram packet from a RadiusPacket to be send.
     *
     * @param packet RadiusPacket
     * @param secret shared secret to encode packet
     * @param request request packet
     * @return new datagram packet
     * @throws IOException
     */
    private byte[] makeBytePacket(RadiusPacket packet, String secret, RadiusPacket request)
            throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        packet.encodeResponsePacket(bos, secret, request);
        byte[] data = bos.toByteArray();

        return data;
    }

    /**
     * Creates a RadiusPacket for a Radius request from a received datagram
     * packet.
     *
     * @param packet received datagram
     * @return RadiusPacket object
     * @exception RadiusException malformed packet
     * @exception IOException communication error (after getRetryCount()
     * retries)
     */
    private RadiusPacket makeRadiusPacket(byte[] packet, String sharedSecret, int forceType) throws IOException, RadiusException {

        ByteArrayInputStream in = new ByteArrayInputStream(packet);
        RadiusPacket rp = RadiusPacket.decodeRequestPacket(in, sharedSecret, forceType);
        return rp;
    }

    private SSLContext sslContext = null;
    private ServerSocketFactory socketFactory = null;
    private int backlog = 50;
    private ServerSocket authSocket = null;
    private ServerSocket acctSocket = null;
    private static Logger logger = LoggerFactory.getLogger(RadSecRadiusServer.class);

}
