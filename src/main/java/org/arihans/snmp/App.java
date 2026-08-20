package org.arihans.snmp;

import org.snmp4j.agent.io.ImportMode;

import java.util.Arrays;

/**
 * Hello world!
 *
 */
public class App 
{
    public static void main( String[] args )
    {
        try {
            System.out.println("Welcome to SNMP Device Simulator");
            String address = "127.0.0.1/1161";
            SnmpAgent snmpAgent = new SnmpAgent(address);

            System.out.println("Initializing SNMP Agent");
            snmpAgent.init();
            snmpAgent.loadConfig(ImportMode.REPLACE_CREATE);
            snmpAgent.run();

            System.out.println(" SNMP Agent is running and listening ....");
            //keep main thread alive
            while(true){
                Thread.sleep(5000);
            }



        }
        catch(Exception e){

        }
    }
}
