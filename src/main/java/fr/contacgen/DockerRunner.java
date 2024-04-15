package fr.contacgen;

import static fr.contacgen.ConTacGenUtils.dockerContainerExists;
import static fr.contacgen.ConTacGenUtils.dockerCp;
import static fr.contacgen.ConTacGenUtils.dockerExec;
import static fr.contacgen.ConTacGenUtils.dockerImageExists;
import static fr.contacgen.ConTacGenUtils.dockerInspectIP;
import static fr.contacgen.ConTacGenUtils.dockerPull;
import static fr.contacgen.ConTacGenUtils.dockerRm;
import static fr.contacgen.ConTacGenUtils.dockerRun;
import static fr.contacgen.ConTacGenUtils.dockerStop;
import static fr.contacgen.ConTacGenUtils.getDockerClient;
import static fr.contacgen.ConTacGenUtils.readPcap;

import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.util.function.Consumer;

import com.github.dockerjava.api.DockerClient;
import com.github.dockerjava.api.async.ResultCallback.Adapter;
import com.github.dockerjava.api.model.Frame;

public class DockerRunner {

	private DockerRunner() {}

	/**
	 * Run a docker container.
	 * Execute the payload.sh script in the container.
	 * Execute the attack in the container.
	 * Copy the pcap file from the container to the host.
	 * Stop the container.
	 * Remove the container.
	 * Parse the pcap file.
	 * And manage the multi-threading.
	 * 
	 * @param dockerImage the docker image to run
	 * @throws InterruptedException 
	 * @throws IOException 
	 */
	public static ConTacGenPacketHandler dockerMain(String dockerImage, Consumer<InetAddress> toRun, int duration) throws InterruptedException, IOException {
		File tmpFile = new File(System.getProperty("java.io.tmpdir") + "/capture.pcap");
		System.out.println("Run Docker");

		// Docker parameters
		String containerName = "udpattack";
		String containerFile = "/data/capture.pcap";

		// Get the Docker client
		System.out.println("Get Docker client");
		DockerClient dockerClient = getDockerClient();
		if(dockerClient == null)
			throw new IllegalStateException("Could not connect to docker !");

		// Check if the container is already running
		if (dockerContainerExists(containerName, dockerClient)) {
			System.out.println("Container already exists, stopping");
			dockerStop(containerName, dockerClient);
			dockerRm(containerName, dockerClient);
		}

		// Check if the image exists
		if (!dockerImageExists(dockerImage, dockerClient)) {
			// Pull the image
			dockerPull(dockerImage, dockerClient);
		}

		// Run the container
		dockerRun(dockerImage, containerName, dockerClient);
		Adapter<Frame> exec = dockerExec("./payload.sh -d " + duration, containerName, dockerClient);

		// Get the IP address of the container
		String ipAddress = dockerInspectIP(containerName, dockerClient);
		InetAddress address = InetAddress.getByName(ipAddress);

		// Start UDP DOS
		System.out.println("Start UDP DOS");
		Runnable task = () -> toRun.accept(address);
		Thread attack = new Thread(task);
		attack.start();

		exec.awaitCompletion();
		attack.join();

		dockerCp(tmpFile, containerName, containerFile, dockerClient);

		dockerStop(containerName, dockerClient);

		dockerRm(containerName, dockerClient);

		// DEBUG LOG
		System.out.println("Stop UDP DOS");

		// Parse the pcap file
		ConTacGenPacketHandler handler = ConTacGenPacketHandler.getInstance();
		handler.clear();

		readPcap(tmpFile, handler);
		tmpFile.delete();
		return handler;
	}
}
