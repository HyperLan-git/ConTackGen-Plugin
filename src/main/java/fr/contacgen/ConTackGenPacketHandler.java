package fr.contacgen;

import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

import io.pkts.PacketHandler;
import io.pkts.packet.Packet;
import io.pkts.protocol.Protocol;

public class ConTackGenPacketHandler implements PacketHandler {
	private static final ConTackGenPacketHandler INSTANCE = new ConTackGenPacketHandler();

	public static final ConTackGenPacketHandler getInstance() {
		return INSTANCE;
	}

	private List<PacketData> data = new ArrayList<PacketData>();
	private Instant startTime = Instant.now();

	private ConTackGenPacketHandler() {}

	@Override
	public boolean nextPacket(Packet packet) throws IOException {
		if(!packet.hasProtocol(Protocol.IPv4) && !packet.hasProtocol(Protocol.IPv6)) return true;
		// Update the timer
		long timeDiffInMillis = packet.getArrivalTime() - startTime.toEpochMilli();
		data.add(new PacketData(packet, timeDiffInMillis));
		return true;
	}

	public ConTackGenPacketHandler clear() {
		data.clear();
		return this;
	}
	
	public ConTackGenPacketHandler foreach(Consumer<PacketData> action) {
		data.forEach(action);
		return this;
	}
}
