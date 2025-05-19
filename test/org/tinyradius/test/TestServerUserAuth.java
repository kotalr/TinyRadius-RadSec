/**
 * $Id: TestServer.java,v 2.0 2011/11/08 07:23:18 AM wiora Exp $
 * Created on 08.04.2005
 * @author Matthias Wuttke, Matthias Wiora
 * 1.6 Original Version TinyRadius "TestServer.java" wuttke
 * @version $Revision: 1.0 $
 */
package org.tinyradius.test;

import java.io.IOException;

import java.io.FileInputStream;
import java.io.InputStream;

import java.util.Properties;

import java.net.InetSocketAddress;

import org.tinyradius.packet.AccessRequest;
import org.tinyradius.packet.RadiusPacket;
import org.tinyradius.util.RadiusException;
import org.tinyradius.util.RadiusServer;

/**
 * Test server which terminates after 30 s.
 * Knows only the client "localhost" with secret "testing123" and
 * the user "mw" with the password "test".
 */
public class TestServerUserAuth {
	
	public static void main(String[] args) 
	throws IOException, Exception {
		Properties prop = new Properties();
		String fileName = "tinyradius.config";
		InputStream appConfig = new FileInputStream(fileName);
		
		prop.load(appConfig);
		
		RadiusServer server = new RadiusServer() {
			// Authorize localhost/testing123
			public String getSharedSecret(InetSocketAddress client, String radiusClient, String radiusSecret) {
				if (client.getAddress().getHostAddress().equals(radiusClient))
					return radiusSecret;
				else
					return null;
			}
			
			// Authenticate mw
			public String getUserPassword(String userName) {
				if (userName.equals("mw"))
					return "test";
				else
					return null;
			}
			
			// Adds an attribute to the Access-Accept packet
			public RadiusPacket accessRequestReceived(AccessRequest accessRequest, InetSocketAddress client) 
			throws RadiusException {
				System.out.println("Received Access-Request:\n" + accessRequest);
				RadiusPacket packet = super.accessRequestReceived(accessRequest, client);
				if (packet.getPacketType() == RadiusPacket.ACCESS_ACCEPT)
					packet.addAttribute("Reply-Message", "successfully authenticated " + accessRequest.getUserName() + " by user auth");
				if (packet == null)
					System.out.println("Ignore packet.");
				else
					System.out.println("Answer:\n" + packet);
				return packet;
			}

			public boolean getExternalAuth(String userName, String passCode) {
				// TODO Auto-generated method stub
				return false;
			}
		};
		server.setRadiusClient(prop.getProperty("radius.client"));
		server.setRadiusSecret(prop.getProperty("radius.secret"));
		server.setAuthPort(Integer.parseInt(prop.getProperty("radius.authport")));
		server.setAcctPort(Integer.parseInt(prop.getProperty("radius.acctport")));
		server.setAuthMethod("user");
		
		server.start(true, true);
		
		System.out.println("userauth server started - never ending");
		
		Thread.sleep(1000*60*30);
		System.out.println("Stop server");
		server.stop();
	}
	
}
