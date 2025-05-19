/**
 * $Id: ExecCommand.java,v v 1.0 2011/11/08 07:23:18 AM wiora Exp $
 * Created on 07.11.2011
 * @author Matthias R. Wiora
 * @version $Revision: 1.0 $
 */
package org.tinyradius.packet;

import java.io.*;
import java.util.ArrayList;

/**
 * This class represents methos to execute commands.
 */
public class ExecCommand extends RadiusPacket {
	
	static public String[] runCommand(String cmd) 
    throws IOException
    {  
    // The actual procedure for process execution:
    // runCommand(String cmd);
    
    // Create a list for storing  output.
    ArrayList list = new ArrayList(); 

    // Execute a command and get its process handle
    Process proc = Runtime.getRuntime().exec(cmd); 

    // Get the handle for the processes InputStream
    InputStream istr = proc.getInputStream(); 

    // Create a BufferedReader and specify it reads 
    // from an input stream.
    BufferedReader br = new BufferedReader(
       new InputStreamReader(istr));
    String str; // Temporary String variable

    // Read to Temp Variable, Check for null then 
    // add to (ArrayList)list
    while ((str = br.readLine()) != null) list.add(str);
    
    // Wait for process to terminate and catch any Exceptions.
    try { proc.waitFor(); } 
    catch (InterruptedException e) {
      System.err.println("Process was interrupted"); }

    // Note: proc.exitValue() returns the exit value. 
    // (Use if required)

    br.close(); // Done.

    // Convert the list to a string and return
    return (String[])list.toArray(new String[0]); 
 	}
	
	static public int runCommandReturnExitCode(String cmd) 
    throws IOException
    {  
    // The actual procedure for process execution:
    // runCommand(String cmd);
    
    // Create a list for storing  output.
    ArrayList list = new ArrayList(); 

    // Execute a command and get its process handle
    Process proc = Runtime.getRuntime().exec(cmd); 

    // Get the handle for the processes InputStream
    InputStream istr = proc.getInputStream(); 

    // Create a BufferedReader and specify it reads 
    // from an input stream.
    BufferedReader br = new BufferedReader(
       new InputStreamReader(istr));
    String str; // Temporary String variable

    // Read to Temp Variable, Check for null then 
    // add to (ArrayList)list
    while ((str = br.readLine()) != null) list.add(str);
    
    // Wait for process to terminate and catch any Exceptions.
    try { proc.waitFor(); } 
    catch (InterruptedException e) {
      System.err.println("Process was interrupted"); }

    // Note: proc.exitValue() returns the exit value. 
    // (Use if required)

    br.close(); // Done.
    
    int procExitValue = proc.exitValue();

    // Convert the list to a string and return
    return procExitValue; 
 	}
}