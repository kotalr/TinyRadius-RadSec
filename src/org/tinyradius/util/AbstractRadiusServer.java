package org.tinyradius.util;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.ExecutorService;
import javax.net.ssl.SSLContext;
import org.tinyradius.dictionary.Dictionary;
import org.tinyradius.packet.AccessRequest;
import org.tinyradius.packet.*;
import org.tinyradius.packet.RadiusPacket;

/**
 * Implements a simple Radius server. This class must be subclassed to provide
 * an implementation for getSharedSecret() and getUserPassword(). If the server
 * supports accounting, it must override accountingRequestReceived().
 */
public interface AbstractRadiusServer {

    public void setExecutor(ExecutorService executor);

    public ExecutorService getExecutor();

    public String getSharedSecret(InetSocketAddress client, String radiusClient, String radiusSecret);

    public String getUserPassword(String userName);

    public boolean getExternalAuth(String userName, String passCode);

    public RadiusPacket accessRequestReceived(AccessRequest accessRequest, InetSocketAddress client) throws RadiusException;

    public RadiusPacket accountingRequestReceived(AccountingRequest accountingRequest, InetSocketAddress client) throws RadiusException;

    public RadiusPacket coaRequestReceived(CoaRequest coaRequest, InetSocketAddress client) throws RadiusException;

    public RadiusPacket disconnectRequestReceived(DisconnectRequest disconnectRequest, InetSocketAddress client) throws RadiusException;

    public RadiusPacket radiusPacketReceived(RadiusPacket radiusPacketRequest, InetSocketAddress client) throws RadiusException;

    public void start(boolean listenAuth, boolean listenAcct);

    public void stop();

    public int getAuthPort();

    public void setAuthPort(int authPort);

    public int getSocketTimeout();

    public void setSocketTimeout(int socketTimeout) throws SocketException;

    public void setAcctPort(int acctPort);

    public int getAcctPort();

    public String getRadiusClient();

    public void setRadiusClient(String radiusClient);

    public String getRadiusSecret();

    public void setRadiusSecret(String radiusSecret);

    public long getDuplicateInterval();

    public void setDuplicateInterval(long duplicateInterval);

    public InetAddress getListenAddress();

    public void setListenAddress(InetAddress listenAddress);

    public String getAuthMethod();

    public void setAuthMethod(String authMethod);

    public String getAppPath();

    public void setAppPath(String appPath);

    public String getAppFolder();

    public void setAppFolder(String appFolder);

    public Dictionary getDictionary();

    public void setDictionary(Dictionary dictionary);

    public void setSSLContext(SSLContext sslContext) throws NoSuchAlgorithmException;
}
