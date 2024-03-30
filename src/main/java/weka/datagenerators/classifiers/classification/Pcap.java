package weka.datagenerators.classifiers.classification;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.Timestamp;
import java.text.SimpleDateFormat;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.time.temporal.TemporalUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Vector;

import org.pcap4j.packet.factory.statik.services.StaticPacketFactoryBinderProvider;
import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapHandle.TimestampPrecision;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapPacket;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV4Packet.IpV4Header;
import org.pcap4j.packet.Packet;

import com.github.dockerjava.api.DockerClient;
import com.github.dockerjava.api.async.ResultCallback;
import com.github.dockerjava.api.command.CreateContainerCmd;
import com.github.dockerjava.api.command.PullImageResultCallback;
import com.github.dockerjava.api.exception.NotFoundException;
import com.github.dockerjava.api.model.Container;
import com.github.dockerjava.api.model.ContainerNetwork;
import com.github.dockerjava.api.model.Frame;
import com.github.dockerjava.api.model.Image;
import com.github.dockerjava.core.DockerClientBuilder;

import weka.core.Attribute;
import weka.core.DenseInstance;
import weka.core.Instance;
import weka.core.Instances;
import weka.core.Option;
import weka.core.RevisionUtils;
import weka.core.Utils;
import weka.datagenerators.ClassificationGenerator;

/**
 * Generates a contexctual dataset of network traffic. The dataset is generated
 * from a simulation of a network traffic. The simulation is done using a
 * docker.
 * The docker container capture the network traffic and save into a pcap file.
 * The pcap file is then parsed to extract the features of the network traffic.
 * It is possible to run some attack on the docker container to generate some
 * specific network traffic.
 * 
 * The available attacks are: UDPDDOS.
 * 
 * The available docker images are:
 * - fersuy/contackgen-ubuntu2204:1.1.0
 * 
 * @author Mathieu Salliot (SanjiKush on GitHub, mathieu.salliot@yahoo.fr).
 * @author Pierre BLAIS (pierreblais or PierreBls on GitHub, pierreblais@hotmail.fr).
 * 
 * @version idk.
 */
@SuppressWarnings("serial")
public class Pcap extends ClassificationGenerator {

	// Dataset attributes
	private static final String[] DATASET_ATTRIBUTES_STRINGS = {
			"srcIp", "dstIp", "srcPort", "dstPort", "type", "headerChecksum"
	};
	private static final String[] DATASET_ATTRIBUTES_NUMERICS = {
			"protocol", "version", "IHL", "length", "identification", "fragmentOffset", "TTL", "timer"
	};
	// private static final String[] DATASET_ATTRIBUTES_TIMESTAMP = { // Useless while there is only one timestamp
	//         "timeStamp"
	// };
	// Dataset attributes
	private static Map<String, Attribute> datasetAttributes = new HashMap<String, Attribute>();

	// Pcap attributes
	private static String[] srcIps;
	private static String[] dstIps;
	private static String[] srcPorts;
	private static String[] dstPorts;
	private static String[] types;
	private static int[] versions;
	private static int[] IHLs;
	private static int[] lengths;
	private static int[] identifications;
	private static int[] fragmentOffsets;
	private static int[] TTLs;
	private static int[] protocols;
	private static String[] headerChecksums;
	private static int[] timer;
	private static Instant[] timeStamps;

	// Generator accepted attribute
	private static final String[] ACCEPTED_DOCKER_IMAGES = {
			"fersuy/contackgen-ubuntu2204:1.1.0"
	};

	// Generator attributes
	protected String dockerImage;
	protected String pcapFullPath;
	protected String timestampFormat;
	protected int duration;
	protected int maxPackets;

	// TimeStamp
	private static Instant startTime;

	/**
	 * Initialize the generator with the default values.
	 */
	public Pcap() {
		super();

		setDockerImage(defaultDockerImage());
		setDuration(defaultDuration());
		setPcapFullPath(defaultPcapFullPath());
		setMaxPackets(defaultMaxPackets());
		setTimestampFormat(defaultTimestampFormat());
	}

	/**
	 * Returns a string describing this data generator.
	 * 
	 * @return a description of the generator suitable for displaying in the
	 *         explorer/experimenter gui.
	 */
	public String globalInfo() {
		return "Generates a contexctual dataset of network traffic. The dataset is generated "
				+ "from a simulation of a network traffic. The simulation is done using a docker."
				+ "The docker container capture the network traffic and save into a pcap file."
				+ "The pcap file is then parsed to extract the features of the network traffic."
				+ "It is possible to run some attack on the docker container to generate some "
				+ "specific network traffic.\n"
				+ "The available attacks are: UDPDDOS.\n"
				+ "The available docker images are:\n"
				+ "- fersuy/contackgen-ubuntu2204:1.1.0\n";
	}

	/**
	 * Returns an enumaratation of the available options.
	 * 
	 * @return an enumeration of all the available options.
	 */
	@Override
	public Enumeration<Option> listOptions() {
		Vector<Option> newVector = enumToVector(super.listOptions());

		newVector.add(new Option("\tThe docker image to use for the simulation. (default: "
				+ defaultDockerImage() + ")", "dockerImage", 1, "-dockerImage <dockerImage>"));
		newVector.add(new Option("\tThe network traffic captur duration. (default: "
				+ defaultDuration() + ")", "duration", 1, "-duration <duration>"));
		newVector.add(new Option("\tThe pcap directory. (default: "
				+ defaultPcapFullPath() + ")", "pcapFullPath", 1, "-pcapFullPath <pcapFullPath>"));
		newVector.add(new Option("\tThe max number of packets to parse. (default: "
				+ defaultMaxPackets() + ")", "maxPackets", 1, "-maxPackets <maxPackets>"));
		newVector.add(new Option("\tThe timestamp format. (default: "
				+ defaultTimestampFormat() + ")", "timestampFormat", 1, "-timestampFormat <timestampFormat>"));

		return newVector.elements();
	}

	/**
	 * Parses a given list of options.
	 * 
	 * @param options the list of options as an array of strings.
	 * @throws Exception if an option is not supported.
	 */
	@Override
	public void setOptions(String[] options) throws Exception {
		super.setOptions(options);

		// Set the docker image
		String dockerImage = Utils.getOption("dockerImage", options);
		if (dockerImage.length() != 0) {
			setDockerImage(dockerImage);
		} else {
			setDockerImage(defaultDockerImage());
		}

		// Set the duration
		int duration = Integer.parseInt(Utils.getOption("duration", options));
		if (duration != 0) {
			setDuration(duration);
		} else {
			setDuration(defaultDuration());
		}

		// Set the pcap directory
		String pcapDir = Utils.getOption("pcapFullPath", options);
		if (pcapDir.length() != 0) {
			setPcapFullPath(pcapDir);
		} else {
			setPcapFullPath(defaultPcapFullPath());
		}

		// Set the max number of packets
		int maxPackets = Integer.parseInt(Utils.getOption("maxPackets", options));
		if (maxPackets != 0) {
			setMaxPackets(maxPackets);
		} else {
			setMaxPackets(defaultMaxPackets());
		}

		// Set the timestamp format
		String timestampFormat = Utils.getOption("timestampFormat", options);
		if (timestampFormat.length() != 0) {
			setTimestampFormat(timestampFormat);
		} else {
			setTimestampFormat(defaultTimestampFormat());
		}
	}

	/**
	 * Gets the current settings of the generator.
	 * 
	 * @return an array of strings suitable for passing to setOptions.
	 */
	@Override
	public String[] getOptions() {
		Vector<String> newVector = new Vector<String>();
		String[] options = super.getOptions();
		for (int i = 0; i < options.length; i++) {
			newVector.add(options[i]);
		}

		// Add the docker image
		newVector.add("-dockerImage");
		newVector.add(getDockerImage());

		// Add the duration
		newVector.add("-duration");
		newVector.add("" + getDuration());

		// Add the pcap directory
		newVector.add("-pcapFullPath");
		newVector.add(getPcapFullPath());

		// Add the max number of packets
		newVector.add("-maxPackets");
		newVector.add("" + getMaxPackets());

		// Add the timestamp format
		newVector.add("-timestampFormat");
		newVector.add(getTimestampFormat());

		return newVector.toArray(new String[0]);
	}

	/**
	 * returns the default Docker image.
	 * 
	 * @return the default Docker image.
	 */
	protected String defaultDockerImage() {
		return "fersuy/contackgen-ubuntu2204:1.1.0";
	}

	/**
	 * returns the default duration.
	 * 
	 * @return the default duration.
	 */
	protected int defaultDuration() {
		return 10;
	}

	/**
	 * returns the default pcap directory.
	 * 
	 * @return the default pcap directory.
	 */
	protected String defaultPcapFullPath() {
		return System.getProperty("java.io.tmpdir") + "/capture.pcap";
	}

	/**
	 * returns the default max number of packets.
	 * 
	 * @return the default max number of packets.
	 */
	protected int defaultMaxPackets() {
		return 1000;
	}

	/**
	 * returns the default timestamp format.
	 * 
	 * @return the default timestamp format.
	 */
	protected String defaultTimestampFormat() {
		return "yyyy-MM-dd HH:mm:ss.SSS";
	}

	/**
	 * Gets the Docker image.
	 * 
	 * @return the Docker image.
	 */
	public String getDockerImage() {
		return dockerImage;
	}

	/**
	 * Gets the duration.
	 * 
	 * @return the duration.
	 */
	public int getDuration() {
		return duration;
	}

	/**
	 * Gets the pcap directory.
	 * 
	 * @return the pcap directory.
	 */
	public String getPcapFullPath() {
		return pcapFullPath;
	}

	/**
	 * Gets the max number of packets.
	 * 
	 * @return the max number of packets.
	 */
	public int getMaxPackets() {
		return maxPackets;
	}

	/**
	 * Gets the timestamp format.
	 * 
	 * @return the timestamp format.
	 */
	public String getTimestampFormat() {
		return timestampFormat;
	}

	/**
	 * Sets the Docker image.
	 * 
	 * @param dockerImage the Docker image.
	 */
	public void setDockerImage(String dockerImage) {
		if (Arrays.asList(ACCEPTED_DOCKER_IMAGES).contains(dockerImage)) {
			this.dockerImage = dockerImage;
		} else {
			throw new IllegalArgumentException("The docker image " + dockerImage + " is not supported.");
		}
	}

	/**
	 * Sets the duration.
	 * 
	 * @param duration the duration.
	 */
	public void setDuration(int duration) {
		this.duration = duration;
	}

	/**
	 * Sets the pcap directory.
	 * 
	 * @param pcapFullPath the pcap directory.
	 */
	public void setPcapFullPath(String pcapFullPath) {
		// Check if the pcap directory is not empty
		if (pcapFullPath.length() != 0) {
			this.pcapFullPath = defaultPcapFullPath();
		}

		// Extract the pcap directory
		String pcapDir = pcapFullPath.substring(0, pcapFullPath.lastIndexOf("/"));

		// Convert the pcap directory to a Path object
		Path path = Paths.get(pcapDir);

		// Check if the pcap directory exists
		if (!Files.exists(path) || !Files.isDirectory(path)) {
			// Throw an exception if the pcap directory does not exist
			throw new IllegalArgumentException("The pcap directory " + pcapDir + " does not exist.");
		}

		// Create absolute full path
		this.pcapFullPath = path.toAbsolutePath().toString() + "/"
				+ pcapFullPath.substring(pcapFullPath.lastIndexOf("/") + 1);
	}

	/**
	 * Sets the max number of packets.
	 * 
	 * @param maxPackets the max number of packets.
	 */
	public void setMaxPackets(int maxPackets) {
		this.maxPackets = maxPackets;
	}

	/**
	 * Sets the timestamp format.
	 * 
	 * @param timestampFormat the timestamp format.
	 */
	public void setTimestampFormat(String timestampFormat) {
		// Ensure that the timestamp format is valid
		try {
			new SimpleDateFormat(timestampFormat);
		} catch (IllegalArgumentException e) {
			throw new IllegalArgumentException("The timestamp format " + timestampFormat + " is not valid.");
		}

		this.timestampFormat = timestampFormat;
	}

	/**
	 * Initializes the format for the dataset produced. Must be called before the
	 * generateExample or generateExamples methods are used.
	 *
	 * Basicaly Re-initializes the random number generator with the given seed. But
	 * NOT IN OUR USECASE, we don't use random seed because or datagenration is
	 * contexctual and not unitary and reproduceable
	 * 
	 * @return the format for the dataset
	 * @throws Exception if the generating of the format failed
	 * @see #getSeed()
	 */
	@Override
	public Instances defineDataFormat() throws Exception {
		// Set up the attributes
		ArrayList<Attribute> atts = new ArrayList<Attribute>();

		// Define the String attributes
		for (String attribute : DATASET_ATTRIBUTES_STRINGS) {
			Attribute m_att = new Attribute(attribute, (ArrayList<String>) null);
			datasetAttributes.put(attribute, m_att);
			atts.add(m_att);
		}

		// Define the Numeric attributes
		for (String attribute : DATASET_ATTRIBUTES_NUMERICS) {
			Attribute m_att = new Attribute(attribute);
			datasetAttributes.put(attribute, m_att);
			atts.add(m_att);
		}

		// Define the timestamp attribute
		Attribute m_att = new Attribute("timestamp", getTimestampFormat());
		datasetAttributes.put("timestamp", m_att);
		atts.add(m_att);

		m_DatasetFormat = new Instances(getRelationNameToUse(), atts, 0);

		return m_DatasetFormat;
	}

	/**
	 * Do nothing because the dataset is already isn't unatrily generated.
	 * (basicaly the generateExamples call the generateExample method
	 * several times to generate the dataset, in our case the generateExamples
	 * will genereted the dataset without unitary and reproduceable action)
	 * 
	 * @return null
	 * @throws Exception if the example could not be generated
	 */
	@Override
	public Instance generateExample() throws Exception {
		return null;
	}

	/**
	 * Generates a dataset of network traffic.
	 * 
	 * (Look like our main function)
	 * 
	 * @return the generated dataset
	 * @throws Exception if the format of the dataset is not defined
	 * @throws Exception if the dataset could not be generated
	 */
	@Override
	public Instances generateExamples() throws Exception {
		System.out.println("Generating dataset...");

		// Check if the dataset format is defined
		if (m_DatasetFormat == null) {
			throw new Exception("Dataset format not defined.");
		}

		// Start the docker container
		dockerMain(getDockerImage(), getDuration(), getPcapFullPath());

		Instances result = new Instances(m_DatasetFormat, 0);
		for (int i = 0; i < getMaxPackets(); i++) {
			// Equivalent to the generateExample method

			// Create a new instance with the same format as the dataset
			Instance instance = new DenseInstance(m_DatasetFormat.numAttributes());
			instance.setDataset(getDatasetFormat());

			// Set the attributes values
			for (Map.Entry<String, Attribute> entry : datasetAttributes.entrySet()) {
				String attKey = entry.getKey();
				Attribute attObj = (Attribute) entry.getValue();

				// Check the type of the attribute
				if (attObj.type() == Attribute.NUMERIC) {
					// Set the value of the numeric attribute
					double attsValue = setNumericAttributeValue(i, attKey);
					instance.setValue(attObj, attsValue);
					continue;
				} else if (attObj.type() == Attribute.STRING) {
					// Set the value of the string attribute
					String attsValue = setStringAttributeValue(i, attKey);

					// Check string value already exist
					if (attObj.indexOfValue(attsValue) == -1) {
						// Add the string value
						int addRes = attObj.addStringValue(attsValue);
						if (addRes == -1) {
							throw new Exception("Error adding string value '" + attsValue + "' to attribute '" + attKey + "' (wrong type).");
						}
					}
					instance.setValue(attObj, attsValue);
					continue;
				} else if (attObj.type() == Attribute.DATE) {
					SimpleDateFormat sdf = new SimpleDateFormat(getTimestampFormat());
					String attsValue = sdf.format(timeStamps[i]);
					double dd = attObj.parseDate(attsValue);
					instance.setValue(attObj, dd);
					continue;
				}
				else {
					throw new Exception("Error setting attribute '" + attKey + "' (wrong type).");
				}
			}

			result.add(instance);
		}

		return result;
	}

	/**
	 * Sets the value of an attribute.
	 * 
	 * @param i the index of the attribute.
	 * @param attKey the name of the attribute.
	 * @return the value of the attribute.
	 */
	private int setNumericAttributeValue(int i, String attKey) {
		// Switch on the attsString to set the attsvalue
		int attsValue = -1;

		// Set the value of the numeric attribute
		if (attKey.equals("version")) {
			attsValue = versions[i];
		} else if (attKey.equals("IHL")) {
			attsValue = IHLs[i];
		} else if (attKey.equals("length")) {
			attsValue = lengths[i];
		} else if (attKey.equals("identification")) {
			attsValue = identifications[i];
		} else if (attKey.equals("fragmentOffset")) {
			attsValue = fragmentOffsets[i];
		} else if (attKey.equals("TTL")) {
			attsValue = TTLs[i];
		} else if (attKey.equals("protocol")) {
			attsValue = protocols[i];
		} else if (attKey.equals("timer")) {
			attsValue = timer[i];
		}

		return attsValue;
	}

	/**
	 * Sets the value of an attribute.
	 * 
	 * @param i the index of the attribute.
	 * @param attKey the name of the attribute.
	 * @return the value of the attribute.
	 */
	private String setStringAttributeValue(int i, String attKey) {
		// Switch on the attsString to set the attsvalue
		String attsValue = "";

		// Set the value of the string attribute
		if (attKey.equals("srcIp")) {
			attsValue = srcIps[i];
		} else if (attKey.equals("dstIp")) {
			attsValue = dstIps[i];
		} else if (attKey.equals("srcPort")) {
			attsValue = srcPorts[i];
		} else if (attKey.equals("dstPort")) {
			attsValue = dstPorts[i];
		} else if (attKey.equals("type")) {
			attsValue = types[i];
		} else if (attKey.equals("headerChecksum")) {
			attsValue = headerChecksums[i];
		}

		return attsValue;
	}

	/**
	 * Generates a comment string that documentates the data generator. By default
	 * this string is added at the beginning of the produced output as ARFF file
	 * type, next after the options.
	 * 
	 * @return string contains info about the generated rules
	 */
	@Override
	public String generateStart() throws Exception {
		return "";
	}

	/**
	 * Generates a comment string that documentates the data generator. By default
	 * this string is added at the end of the produced output as ARFF file type.
	 * 
	 * @return string contains info about the generated rules
	 */
	@Override
	public String generateFinished() throws Exception {
		return null;
	}

	/**
	 * I not understand what is this method for.
	 */
	@Override
	public boolean getSingleModeFlag() throws Exception {
		return false;
	}

	/**
	 * Returns the revision string.
	 * 
	 * @return the revision
	 */
	@Override
	public String getRevision() {
		return RevisionUtils.extract("$Revision: 99999 $");
	}

	/**
	 * Main method for running this data generator.
	 * 
	 * @param args the commandline arguments
	 */
	public static void main(String[] args) {
		runDataGenerator(new Pcap(), args);

		// // Test docker container
		// try {
		//     dockerMain("fersuy/contackgen-ubuntu2204:1.1.0", 10, "/tmp/capture.pcap");
		// } catch (InterruptedException e) {
		//     // TODO Auto-generated catch block
		//     e.printStackTrace();
		// } catch (IOException e) {
		//     // TODO Auto-generated catch block
		//     e.printStackTrace();
		// }

	}

	// ========================================================================
	// The following methods should be implemented in another class
	// ========================================================================

	/**
	 * Parse network traffic from a pcap file.
	 * 
	 * @param pcapFile the pcap file to parse
	 */
	private static void readPcap(String pcapFile) throws PcapNativeException, NotOpenException, InterruptedException {
		System.out.println("Read pcap file: " + pcapFile + "");
		final PcapHandle handle = Pcaps.openOffline(pcapFile, TimestampPrecision.MICRO);

		handle.loop(-1, new PacketListener() {

			@Override
			public void gotPacket(PcapPacket packet) {
				IpV4Packet p = packet.getPacket().get(IpV4Packet.class);
				parsePacket(p);
				// Set the packet timestamp
				timeStamps = ArrayUtils.add(timeStamps, packet.getTimestamp());
				// Update the timer
				long timeDiffInMillis = packet.getTimestamp().minus(startTime.toEpochMilli(), ChronoUnit.MILLIS).toEpochMilli();
				timer = ArrayUtils.add(timer, (int)timeDiffInMillis);
			}
		});

		handle.close();
	}

	/**
	 * Parse a packet from a pcap file.
	 * 
	 * @param packet the packet to parse
	 */
	private static void parsePacket(IpV4Packet packet) {
		System.out.println("Parse packet: " + packet);
		IpV4Header header = packet.getHeader();

		dstIps = ArrayUtils.add(dstIps, header.getDstAddr().toString());
		srcIps = ArrayUtils.add(srcIps, header.getSrcAddr().toString());
		types = ArrayUtils.add(types, header.getProtocol().valueAsString());
		srcPorts = ArrayUtils.add(srcPorts, header.getSrcAddr().toString());
		dstPorts = ArrayUtils.add(dstPorts, header.getDstAddr().toString());
		versions = ArrayUtils.add(versions, header.getVersion().value());
		IHLs = ArrayUtils.add(IHLs, header.getIhlAsInt());
		lengths = ArrayUtils.add(lengths, header.getTotalLengthAsInt());
		identifications = ArrayUtils.add(identifications, header.getIdentificationAsInt());
		fragmentOffsets = ArrayUtils.add(fragmentOffsets, header.getFragmentOffset());
		TTLs = ArrayUtils.add(TTLs, header.getTtlAsInt());
		protocols = ArrayUtils.add(protocols, header.getProtocol().value());
		headerChecksums = ArrayUtils.add(headerChecksums, Integer.toHexString(header.getHeaderChecksum()));
	}

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
	 */
	private static void dockerMain(String dockerImage, int duration, String pcapFullPath)
			throws InterruptedException, IOException {
		System.out.println("Run Docker");

		// Docker parameters
		String containerName = "contackgen-ubuntu2204";
		String containerFile = "/data/capture.pcap";

		// Get the Docker client
		System.out.println("Get Docker client");
		//DockerClient dockerClient = DockerClientBuilder.getInstance().build();

		/*DockerClientConfig config = DefaultDockerClientConfig.createDefaultConfigBuilder()
			    .withDockerHost("npipe:////./pipe/docker_engine")
			    .build();
		DockerHttpClient httpClient = new ApacheDockerHttpClient.Builder()
			    .dockerHost(config.getDockerHost())
			    .maxConnections(100)
			    .connectionTimeout(Duration.ofSeconds(10))
			    .responseTimeout(Duration.ofSeconds(20))
			    .build();
		DockerClient dockerClient = DockerClientImpl.getInstance(config, httpClient);*/
		DockerClient dockerClient = DockerClientBuilder.getInstance().build();
		if(dockerClient == null) {
			throw new IllegalStateException("Could not connect to docker !");
		}

		// Check if the container is already running
		if (dockerContainerExists(containerName, dockerClient)) {
			System.out.println("Container already exists");
			dockerStop(containerName, dockerClient);
			DockerRm(containerName, dockerClient);
		}

		// Check if the image exists
		if (!dockerImageExists(dockerImage, dockerClient)) {
			// Pull the image
			dockerPull(dockerImage, dockerClient);
		}

		// Run the container
		dockerRun(dockerImage, containerName, dockerClient);


		// Sleep 2 seconds
		Thread.sleep(2000);

		// Create the command to execute
		String command = "./payload.sh -d " + duration;
		dockerExec(command, containerName, dockerClient);

		// Sleep 2 seconds
		Thread.sleep(2000);

		// Get the IP address of the container
		String ipAddress = dockerInspectIP(containerName, dockerClient);

		// Start UDP DOS
		System.out.println("Start UDP DOS");
		UDPDos udp = new UDPDos(ipAddress);
		udp.start();

		// Sleep 20 seconds
		Thread.sleep(duration * 1000);

		dockerCp(pcapFullPath, containerName, containerFile, dockerClient);

		dockerStop(containerName, dockerClient);

		DockerRm(containerName, dockerClient);

		// DEBUG LOG
		System.out.println("Stop UDP DOS");

		// Parse the pcap file
		try {
			readPcap(pcapFullPath);
		} catch (PcapNativeException e) {
			e.printStackTrace();
		} catch (NotOpenException e) {
			e.printStackTrace();
		}
	}

	/**
	 * Pull a docker image.
	 * 
	 * @param dockerImage the docker image to pull
	 * @param dockerClient the Docker client
	 * @throws InterruptedException
	 */
	private static void dockerPull(String dockerImage, DockerClient dockerClient) throws InterruptedException {
		System.out.println("Pull image " + dockerImage);
		try {
			dockerClient.pullImageCmd(dockerImage).exec(new PullImageResultCallback()).awaitCompletion();
		} catch (NotFoundException e) {
			throw new RuntimeException("Error while pulling image: " + dockerImage);
		}
	}


	/**
	 * Check if a given Docker image exists localy.
	 * 
	 * @param dockerImage the docker image to run
	 * @param dockerClient the Docker client
	 */
	private static boolean dockerImageExists(String dockerImage, DockerClient dockerClient) {
		System.out.println("Check if image " + dockerImage + " exists localy");
		List<Image> images = dockerClient.listImagesCmd().exec();
		for (Image image : images) {
			for (String repoTag : image.getRepoTags()) {
				if (repoTag.equals(dockerImage)) {
					return true;
				}
			}
		}
		return false;
	}

	/**
	 * Check if a container exists.
	 * 
	 * @param containerName the name of the container
	 * @param dockerClient the Docker client
	 * @return true if the container exists, false otherwise
	 */
	private static boolean dockerContainerExists(String containerName, DockerClient dockerClient) {
		System.out.println("Check if container " + containerName + " is already running");
		List<Container> containers = dockerClient.listContainersCmd().withShowAll(true).exec();
		for (Container container : containers) {
			if (container.getNames()[0].equals("/" + containerName)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Remove the given docker image.
	 * 
	 * @param containerName the name of the container
	 * @param dockerClient the Docker client
	 */
	private static void DockerRm(String containerName, DockerClient dockerClient) {
		// Remove container
		System.out.println("Remove the container " + containerName);
		dockerClient.removeContainerCmd(containerName).exec();
	}

	/**
	 * Stop the given container.
	 * 
	 * @param containerName the name of the container
	 * @param dockerClient the Docker client
	 */
	private static void dockerStop(String containerName, DockerClient dockerClient) {
		// Stop container
		System.out.println("Stop the container " + containerName);
		dockerClient.killContainerCmd(containerName).exec();
	}

	/**
	 * Copy file from container
	 * 
	 * @param pcapFullPath the path of the pcap file
	 * @param containerName the name of the container
	 * @param containerFile the path of the pcap file in the container
	 * @param dockerClient the Docker client
	 * @throws IOException
	 */
	private static void dockerCp(String localPath, String containerName, String containerFile,
			DockerClient dockerClient) throws IOException {
		System.out.println("Copy file from container");
		// Copy file from container
		// try (TarArchiveInputStream tarStream = new TarArchiveInputStream(
		//         dockerClient.copyArchiveFromContainerCmd(containerName,
		//                 containerFile).exec())) {
		//     unTar(tarStream, new File(localPath));
		// } 
		TarArchiveInputStream tarStream = null;
		try {
			tarStream = new TarArchiveInputStream(
					dockerClient.copyArchiveFromContainerCmd(containerName,
							containerFile).exec());
			unTar(tarStream, new File(localPath));
		} finally {
			if (tarStream != null) {
				try {
					tarStream.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		}
	}

	/**
	 * docker Inspect IP address.
	 * 
	 * @param containerName
	 * @param dockerClient
	 * @return the ip address of the container
	 */
	private static String dockerInspectIP(String containerName, DockerClient dockerClient) {
		// Get Ip address
		System.out.println("Get IP address");
		ContainerNetwork network = dockerClient.inspectContainerCmd(containerName).exec().getNetworkSettings()
				.getNetworks().values().iterator().next();
		String ipAddress = network.getIpAddress();
		System.out.println("IP Address: " + ipAddress);
		return ipAddress;
	}

	/**
	 * Exec a command in the container.
	 * 
	 * @param command the command to execute
	 * @param containerName the name of the container
	 * @param dockerClient the Docker client
	 */
	private static void dockerExec(String command, String containerName, DockerClient dockerClient) {
		// Execute the payload.sh in the container
		System.out.println("Execute " + command + " in the container");
		dockerClient
		.execStartCmd(dockerClient.execCreateCmd(containerName).withAttachStdout(true)
				.withCmd("bash", "-c", command).exec().getId())
		.exec(new ResultCallback.Adapter<Frame>());
		// try {
		//     dockerClient
		//             .execStartCmd(dockerClient.execCreateCmd(containerName).withAttachStdout(true)
		//                     .withCmd("bash", "-c", command).exec().getId())
		//             .exec(new ResultCallback.Adapter<>());
		// } catch (NotFoundException e) {
		//     e.printStackTrace();
		// }
	}

	/**
	 * Run a docker container.
	 * 
	 * @param dockerImage the docker image to run
	 * @param containerName the name of the container
	 * @param dockerClient the Docker client
	 */
	private static void dockerRun(String dockerImage, String containerName, DockerClient dockerClient) {
		// Create container
		System.out.println("Create Docker container");
		// try (CreateContainerCmd createContainer = dockerClient
		//         .createContainerCmd(dockerImage).withName(containerName)) {
		//     createContainer.withTty(true);
		//     createContainer.exec();
		// }
		CreateContainerCmd createContainer = null;
		try {
			createContainer = dockerClient
					.createContainerCmd(dockerImage).withName(containerName);
			createContainer.withTty(true);
			createContainer.exec();
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			if (createContainer != null) {
				createContainer.close();
			}
		}

		// Start container
		System.out.println("Start Docker container");
		dockerClient.startContainerCmd(containerName).exec();
		startTime = Instant.now();
	}

	/**
	 * Untar a file.
	 * 
	 * @param tis      the tar input stream
	 * @param destFile the destination file
	 * @throws IOException
	 */
	private static void unTar(TarArchiveInputStream tis, File destFile) throws IOException {
		TarArchiveEntry tarEntry = null;
		while ((tarEntry = tis.getNextTarEntry()) != null) {
			if (tarEntry.isDirectory()) {
				if (!destFile.exists()) {
					destFile.mkdirs();
				}
			} else {
				FileOutputStream fos = new FileOutputStream(destFile);
				IOUtils.copy(tis, fos);
				fos.close();
			}
		}
		tis.close();
	}
}
