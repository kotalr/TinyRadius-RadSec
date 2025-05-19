/**
 * $Id: ExecCommand.java,v 1.4 2011/11/07 09:34:40 AM mrw Exp $
 * Created on 07.11.2011
 * @author Matthias R. Wiora
 * @version $Revision: 1.0 $
 */
package org.tinyradius.test;

import java.io.IOException;

import org.tinyradius.packet.ExecCommand;

/**
 * Simple ExecCommand test
 */
public class TestExecCommand {
	
	/**
	 * Radius command line client.
	 * <br/>Usage: TestClient <i>hostName sharedSecret userName password</i>
	 * @param args arguments
	 * @return 
	 * @throws Exception
	 */
	public static void main(String[] args) {
		 try
	      {
	         // Run and get the output.
	         String outlist[] = ExecCommand.runCommand("ls -la /tmp"); 

	         // Print the output to screen character by character.
	         // Safe and not very inefficient.
	         for (int i = 0; i < outlist.length; i++)
	            System.out.println(outlist[i]);
	      }
	      catch (IOException e) { System.err.println(e); }
	}
}
