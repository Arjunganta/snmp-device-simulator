package org.arihans.snmp;

import org.snmp4j.TransportMapping;
import org.snmp4j.agent.BaseAgent;
import org.snmp4j.agent.CommandProcessor;
import org.snmp4j.agent.DuplicateRegistrationException;
import org.snmp4j.agent.MOAccess;
import org.snmp4j.agent.mo.MOAccessImpl;
import org.snmp4j.agent.mo.MOScalar;
import org.snmp4j.agent.mo.MOTableRow;
import org.snmp4j.agent.mo.snmp.*;
import org.snmp4j.agent.security.MutableVACM;
import org.snmp4j.mp.MPv3;
import org.snmp4j.security.SecurityLevel;
import org.snmp4j.security.SecurityModel;
import org.snmp4j.security.USM;
import org.snmp4j.smi.*;
import org.snmp4j.transport.DefaultUdpTransportMapping;

import java.io.File;
import java.io.IOException;

public class SnmpAgent extends BaseAgent {

    private String address;

    public SnmpAgent(String address){
        //configuration files for storage boot counter and config state
        super(new File("bootCounter.cfg"),new File("snmpAgent.cfg"), new CommandProcessor(new OctetString(MPv3.createLocalEngineID())));
        this.address = address;
    }
    /**
     * Maps and binds the server to target IP address and port
    * */
    @Override
    protected void registerManagedObjects() {

        try{
            //define custom  OID
            OID oid = new OID(".1.3.6.1.4.1.9999.1.1.0");

            //Create a readonly scalar object containing string value
            MOScalar<OctetString> myScaler = new MOScalar<>(oid, MOAccessImpl.ACCESS_READ_ONLY,
                    new OctetString("Hi Welcome to my new SNMP Device simulator"));
            server.register(myScaler,null);

        }
        catch(DuplicateRegistrationException duplicateRegistrationException){
            System.err.println("Error while registering the OID "+duplicateRegistrationException.getMessage());
        }

    }

    @Override
    protected void unregisterManagedObjects() {

    }

    @Override
    protected void addUsmUser(USM usm) {

    }

    @Override
    protected void addNotificationTargets(SnmpTargetMIB snmpTargetMIB, SnmpNotificationMIB snmpNotificationMIB) {

    }

    @Override
    protected void addViews(VacmMIB vacmMIB) {
        // Give 'cReadGroup' read access to the entire OID subtree structure
        vacmMIB.addGroup(SecurityModel.SECURITY_MODEL_SNMPv2c,
                new OctetString("cReadGroup"),
                new OctetString("vReadGroup"),
                StorageType.nonVolatile);

        vacmMIB.addAccess(new OctetString("vReadGroup"),
                new OctetString(),
                SecurityModel.SECURITY_MODEL_ANY,
                SecurityLevel.NOAUTH_NOPRIV,
                MutableVACM.VACM_MATCH_EXACT,
                new OctetString("fullReadView"),
                new OctetString(),
                new OctetString(),
                StorageType.nonVolatile);

        vacmMIB.addViewTreeFamily(new OctetString("fullReadView"),
                new OID(".1.3.6"),
                new OctetString(),
                VacmMIB.vacmViewIncluded,
                StorageType.nonVolatile);

    }

    @Override
    protected void addCommunities(SnmpCommunityMIB snmpCommunityMIB) {
        Variable[] com2sec = new Variable[] {
                new OctetString("public"),       // Community name
                new OctetString("cReadGroup"),   // Security name
                getAgent().getContextEngineID(), // Local engine ID
                new OctetString("public"),       // Context name
                new OctetString(),               // Transport tag
                new Integer32(StorageType.nonVolatile),
                new Integer32(RowStatus.active)
        };
        MOTableRow row = snmpCommunityMIB.getSnmpCommunityEntry().createRow(
                new OctetString("public").toSubIndex(true), com2sec);
        snmpCommunityMIB.getSnmpCommunityEntry().addRow((SnmpCommunityMIB.SnmpCommunityEntryRow) row);
    }

    @Override
    protected void initTransportMappings() throws IOException {
        transportMappings = new TransportMapping<?>[1];
        Address transportAddress = GenericAddress.parse(address);
        transportMappings[0] = new DefaultUdpTransportMapping((UdpAddress) transportAddress);
    }
}
