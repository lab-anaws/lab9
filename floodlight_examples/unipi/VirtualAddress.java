package net.floodlightcontroller.unipi;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.projectfloodlight.openflow.protocol.OFMatchBmap;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFPacketIn;
import org.projectfloodlight.openflow.protocol.OFPacketOut;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.action.OFActionOutput;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.IpProtocol;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.OFBufferId;
import org.projectfloodlight.openflow.types.OFPort;
import org.projectfloodlight.openflow.util.HexString;
import org.python.constantine.platform.darwin.IPProto;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.ICMP;
import net.floodlightcontroller.packet.IPacket;
import net.floodlightcontroller.packet.IPv4;

public class VirtualAddress implements IOFMessageListener, IFloodlightModule {
	
	protected IFloodlightProviderService floodlightProvider; // Reference to the provider
	
	// IP and MAC address for our logical load balancer
	private final static IPv4Address SERVER_IP = IPv4Address.of("8.8.8.8");
	private final static MacAddress SERVER_MAC =  MacAddress.of("00:00:00:00:00:FE");

	@Override
	public String getName() {
		return VirtualAddress.class.getSimpleName();
	}

	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		Collection<Class<? extends IFloodlightService>> l = new ArrayList<Class<? extends IFloodlightService>>();
	    l.add(IFloodlightProviderService.class);
	    return l;
	}

	@Override
	public void init(FloodlightModuleContext context) throws FloodlightModuleException {
		// TODO Auto-generated method stub
		floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
	}

	@Override
	public void startUp(FloodlightModuleContext context) throws FloodlightModuleException {
		floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
	}

	@Override
	public net.floodlightcontroller.core.IListener.Command receive(IOFSwitch sw, OFMessage msg,
			FloodlightContext cntx) {
			
			Ethernet eth = IFloodlightProviderService.bcStore.get(cntx,
                IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
			
			IPacket pkt = eth.getPayload();

			// Print the source MAC address
			Long sourceMACHash = Ethernet.toLong(eth.getSourceMACAddress().getBytes());
			System.out.printf("MAC Address: {%s} seen on switch: {%s}\n",
			HexString.toHexString(sourceMACHash),
			sw.getId());
			
			// Cast to Packet-In
			OFPacketIn pi = (OFPacketIn) msg;

	        // Dissect Packet included in Packet-In
			if (eth.isBroadcast() || eth.isMulticast()) {
				if (pkt instanceof ARP) {
					
					System.out.printf("Processing ARP request\n");
					
					// Process ARP request
					handleARPRequest(sw, pi, cntx);
					
					// Interrupt the chain
					return Command.STOP;
				}
			} else {
				if (pkt instanceof IPv4) {
					
					System.out.printf("Processing IPv4 packet\n");
					
					IPv4 ip_pkt = (IPv4) pkt;
					
					if(ip_pkt.getDestinationAddress().compareTo(SERVER_IP) == 0){
						handleIPPacket(sw, pi, cntx);
						
						// Interrupt the chain
						return Command.STOP;
					}
				}
			}
			
			// Interrupt the chain
			return Command.CONTINUE;

	}
	
	private void handleARPRequest(IOFSwitch sw, OFPacketIn pi,
			FloodlightContext cntx) {

		// Double check that the payload is ARP
		Ethernet eth = IFloodlightProviderService.bcStore.get(cntx,
				IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
		
		if (! (eth.getPayload() instanceof ARP))
			return;
		
		// Cast the ARP request
		ARP arpRequest = (ARP) eth.getPayload();
				
		// Generate ARP reply
		IPacket arpReply = new Ethernet()
			.setSourceMACAddress(SERVER_MAC)
			.setDestinationMACAddress(eth.getSourceMACAddress())
			.setEtherType(EthType.ARP)
			.setPriorityCode(eth.getPriorityCode())
			.setPayload(
				new ARP()
				.setHardwareType(ARP.HW_TYPE_ETHERNET)
				.setProtocolType(ARP.PROTO_TYPE_IP)
				.setHardwareAddressLength((byte) 6)
				.setProtocolAddressLength((byte) 4)
				.setOpCode(ARP.OP_REPLY)
				.setSenderHardwareAddress(SERVER_MAC) // Set my MAC address
				.setSenderProtocolAddress(SERVER_IP) // Set my IP address
				.setTargetHardwareAddress(arpRequest.getSenderHardwareAddress())
				.setTargetProtocolAddress(arpRequest.getSenderProtocolAddress()));
		
		// Create the Packet-Out and set basic data for it (buffer id and in port)
		OFPacketOut.Builder pob = sw.getOFFactory().buildPacketOut();
		pob.setBufferId(OFBufferId.NO_BUFFER);
		pob.setInPort(OFPort.ANY);
		
		// Create action -> send the packet back from the source port
		OFActionOutput.Builder actionBuilder = sw.getOFFactory().actions().buildOutput();
		actionBuilder.setPort(pi.getInPort()); 
		
		// Assign the action
		pob.setActions(Collections.singletonList((OFAction) actionBuilder.build()));
		
		// Set the ARP reply as packet data 
		byte[] packetData = arpReply.serialize();
		pob.setData(packetData);
		
		System.out.printf("Sending out ARP reply\n");
		
		sw.write(pob.build());
		
	}

	private void handleIPPacket(IOFSwitch sw, OFPacketIn pi,
			FloodlightContext cntx) {

		// Double check that the payload is IPv4
		Ethernet eth = IFloodlightProviderService.bcStore.get(cntx,
				IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
		if (! (eth.getPayload() instanceof IPv4))
			return;
		
		// Cast the IP packet
		IPv4 ipv4 = (IPv4) eth.getPayload();

		// Check that the IP is actually an ICMP request
		if (! (ipv4.getPayload() instanceof ICMP))
			return;

		// Cast to ICMP packet
		ICMP icmpRequest = (ICMP) ipv4.getPayload();
			
		// Generate ICMP reply
		IPacket icmpReply = new Ethernet()
			.setSourceMACAddress(SERVER_MAC)
			.setDestinationMACAddress(eth.getSourceMACAddress())
			.setEtherType(EthType.IPv4)
			.setPriorityCode(eth.getPriorityCode())
			.setPayload(
				new IPv4()
				.setProtocol(IpProtocol.ICMP)
				.setDestinationAddress(ipv4.getSourceAddress())
				.setSourceAddress(SERVER_IP)
				.setTtl((byte)64)
				.setProtocol(IpProtocol.IPv4)
				// Set the same payload included in the request
				.setPayload(
						new ICMP()
						.setIcmpType(ICMP.ECHO_REPLY)
						.setIcmpCode(icmpRequest.getIcmpCode())
                        .setPayload(icmpRequest.getPayload())
				)
				);
		
		// Create the Packet-Out and set basic data for it (buffer id and in port)
		OFPacketOut.Builder pob = sw.getOFFactory().buildPacketOut();
		pob.setBufferId(OFBufferId.NO_BUFFER);
		pob.setInPort(OFPort.ANY);
		
		// Create action -> send the packet back from the source port
		OFActionOutput.Builder actionBuilder = sw.getOFFactory().actions().buildOutput();
		actionBuilder.setPort(pi.getInPort()); 
		
		// Assign the action
		pob.setActions(Collections.singletonList((OFAction) actionBuilder.build()));
		
		// Set the ICMP reply as packet data 
		byte[] packetData = icmpReply.serialize();
		pob.setData(packetData);
		
		sw.write(pob.build());
		
	}

}
