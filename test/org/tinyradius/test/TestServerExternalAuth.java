/**
 * $Id: RadiusVerifyer.java,v 1.0 2011/11/08 07:23:18 AM wiora Exp $
 * Created on 07.11.2011 wiora
 * @author Matthias Wuttke, Matthias R. Wiora
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
import org.tinyradius.packet.ExecCommand;

import org.tinyradius.util.RadiusException;
import org.tinyradius.util.RadiusServer;

public class TestServerExternalAuth {
	
	public static void main(String[] args) 
	throws IOException, Exception {
		Properties prop = new Properties();
	    String fileName = "tinyradius.config";
	    InputStream appConfig = new FileInputStream(fileName);

	    prop.load(appConfig);
		
		RadiusServer server = new RadiusServer() {
			// Authorize radiusClient/radiusSecret
			public String getSharedSecret(InetSocketAddress client, String radiusClient, String radiusSecret) {
				if (client.getAddress().getHostAddress().equals(radiusClient))
					return radiusSecret;
				else
					return null;
			}

			
			// Authentication provider (external)
			public boolean getExternalAuth(String userName, String userPassword) {
				 boolean status = false;
				 try
			      {
					 String procCommand = getAppPath() + " " + getAppFolder() + " " + userName + " " + userPassword + "";
					 System.err.println("\bExternal Application command: " + procCommand);
					 int procExitValue = ExecCommand.runCommandReturnExitCode(procCommand); 
					 System.err.println("\bExternal Application command return: " + procExitValue);
					 if(procExitValue == 0) { 
			        	 status = true; 
			        	 }
			      }
			      catch (IOException e) { System.err.println(e); }
			      return status;
			}
			
			// Adds an attribute to the Access-Accept packet
			public RadiusPacket accessRequestReceived(AccessRequest accessRequest, InetSocketAddress client) 
			throws RadiusException {
				System.out.println("Received Access-Request:\n" + accessRequest);
				RadiusPacket packet = super.accessRequestReceived(accessRequest, client);
				if (packet.getPacketType() == RadiusPacket.ACCESS_ACCEPT)
					packet.addAttribute("Reply-Message", "successfully authenticated " + accessRequest.getUserName() + " by external auth");
				if (packet == null)
					System.out.println("Ignore packet.");
				else
					System.out.println("Answer:\n" + packet);
				return packet;
			}

			public String getSharedSecret(InetSocketAddress client) {
				// TODO Auto-generated method stub
				return null;
			}


			public String getUserPassword(String userName) {
				// TODO Auto-generated method stub
				return null;
			}

		};
		server.setRadiusClient(prop.getProperty("radius.client"));
		server.setRadiusSecret(prop.getProperty("radius.secret"));
		server.setAuthPort(Integer.parseInt(prop.getProperty("radius.authport")));
		server.setAcctPort(Integer.parseInt(prop.getProperty("radius.acctport")));
		server.setAppPath(prop.getProperty("externalauth.app"));
		server.setAppFolder(prop.getProperty("externalauth.folder"));
		server.setAuthMethod("external");
		
		server.start(true, true);
		
		System.out.println("externauth server started - never ending");
		
		//Thread.sleep(1000*60*30);
		//System.out.println("Stop server");
		//server.stop();
	}
	
}
