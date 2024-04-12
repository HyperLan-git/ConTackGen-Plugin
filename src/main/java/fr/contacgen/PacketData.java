package fr.contacgen;

import java.io.IOException;

import io.pkts.packet.IPPacket;
import io.pkts.packet.IPv4Packet;
import io.pkts.packet.IPv6Packet;
import io.pkts.packet.Packet;
import io.pkts.protocol.Protocol;

public class PacketData {
	private final String srcIP, dstIP, type, checksum, content;
	private final int version, headerLength, totalLength, id, fragmentOffset, TTL;
	private final long protocol, timestamp, timer;

	public PacketData(Packet packet, long timer) throws IOException {
		IPPacket p;
		if(packet.hasProtocol(Protocol.IPv4)) {
			p = (IPv4Packet) packet.getPacket(Protocol.IPv4);
			this.checksum = Integer.toHexString(((IPv4Packet) p).getIpChecksum());
			this.TTL = ((IPv4Packet) p).getTimeToLive();
			this.type = ((IPv4Packet) p).getProtocol().getName();
		} else if(packet.hasProtocol(Protocol.IPv6)) {
			// TODO get the correct header for port
			p = (IPv6Packet) packet.getPacket(Protocol.IPv6);
			this.checksum = "null";
			this.TTL = ((IPv6Packet) p).getHopLimit();
			this.type = ((IPv6Packet) p).getProtocol().getName();
		} else throw new IllegalArgumentException("Not an IPv4 or IPv6 packet !");
		this.srcIP = p.getSourceIP();
		this.dstIP = p.getDestinationIP();

		this.version = p.getVersion();
		this.headerLength = p.getHeaderLength();
		this.totalLength = p.getTotalIPLength();
		this.id = p.getIdentification();
		this.fragmentOffset = p.getFragmentOffset();
		this.protocol = p.getProtocol().getLinkType() == null ? 0 : p.getProtocol().getLinkType();
		this.timestamp = p.getArrivalTime();
		this.content = p.getPayload().dumpAsHex();
		this.timer = timer;
	}

	public String getSrcIP() {
		return srcIP;
	}

	public String getDstIP() {
		return dstIP;
	}

	public String getType() {
		return type;
	}

	public String getChecksum() {
		return checksum;
	}

	public int getVersion() {
		return version;
	}

	public int getHeaderLength() {
		return headerLength;
	}

	public int getTotalLength() {
		return totalLength;
	}

	public int getId() {
		return id;
	}

	public int getFragmentOffset() {
		return fragmentOffset;
	}

	public int getTTL() {
		return TTL;
	}

	public long getTimer() {
		return timer;
	}

	public long getProtocol() {
		return protocol;
	}

	public long getTimestamp() {
		return timestamp;
	}

	public String getContentHex() {
		return content;
	}
}
