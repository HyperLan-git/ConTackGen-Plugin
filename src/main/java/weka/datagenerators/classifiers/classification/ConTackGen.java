package weka.datagenerators.classifiers.classification;

import static fr.contacgen.ConTacGenUtils.defaultDockerImage;
import static fr.contacgen.ConTacGenUtils.defaultDuration;
import static fr.contacgen.ConTacGenUtils.defaultMaxPackets;

import java.io.IOException;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;

import fr.contacgen.ConTacGenPacketHandler;
import fr.contacgen.DockerRunner;
import fr.contacgen.PacketData;
import fr.contacgen.UDPDos;
import weka.core.Attribute;
import weka.core.DenseInstance;
import weka.core.Instance;
import weka.core.Instances;
import weka.core.Option;
import weka.core.Utils;
import weka.datagenerators.ClassificationGenerator;

/**
 * Generates a contextual data set of network traffic. The data set is generated
 * from a simulation of a network traffic. The simulation is done using a
 * docker container.
 * The docker container captures the network traffic and saves packets into a ".pcap" file.
 * The pcap file is then parsed to extract the features of the network traffic.
 * It is possible to run some attack on the docker container to generate some
 * specific network traffic.
 * 
 * The available attacks are: UDPDDOS.
 * 
 * 
 * @author Mathieu Salliot (SanjiKush on GitHub, mathieu.salliot@yahoo.fr).
 * @author Pierre BLAIS (pierreblais or PierreBls on GitHub, pierreblais@hotmail.fr).
 * 
 * @version 1.0
 */
@SuppressWarnings("serial")
public class ConTackGen extends ClassificationGenerator {
	public static final String DATE_STRING = "yyyy-MM-dd HH:mm:ss";

	// Data set attributes
	private static final Attribute[] DATASET_ATTRIBUTES = new Attribute[] {
			new Attribute("srcIp", true),
			new Attribute("dstIp", true),
			new Attribute("type", true),
			new Attribute("headerChecksum", true),
			new Attribute("protocol"),
			new Attribute("version"),
			new Attribute("IHL"),
			new Attribute("length"),
			new Attribute("identification"),
			new Attribute("fragmentOffset"),
			new Attribute("TTL"),
			new Attribute("timer"),
			new Attribute("timestamp", DATE_STRING),
			new Attribute("content", true)
	};

	// Generator attributes
	private String dockerImage = defaultDockerImage();
	private int duration = defaultDuration();

	/**
	 * Returns a string describing this data generator.
	 * 
	 * @return a description of the generator suitable for displaying in the
	 *         explorer/experimenter gui.
	 */
	public String globalInfo() {
		return "Generates a contextual data set of network traffic. The data set is generated "
				+ "from a simulation of a network traffic. The simulation is done using a docker."
				+ "The docker container capture the network traffic and save into a pcap file."
				+ "The pcap file is then parsed to extract the features of the network traffic."
				+ "It is possible to run some attack on the docker container to generate some "
				+ "specific network traffic.\n"
				+ "The available attacks are: UDPDDOS.\n";
	}

	public static final Option[] OPTIONS = {
			new Option("\tThe docker image to use for the simulation. (default: " + defaultDockerImage() + ")", "dockerImage", 1, "-dockerImage <dockerImage>"),
			new Option("\tThe network traffic captur duration. (default: " + defaultDuration() + ")", "duration", 1, "-duration <duration>")
	};

	/**
	 * @return an enumeration of all the available options.
	 */
	@Override
	public Enumeration<Option> listOptions() {
		Collection<Option> newVector = enumToVector(super.listOptions());
		newVector.addAll(Arrays.asList(OPTIONS));
		return Collections.enumeration(newVector);
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
		String image = Utils.getOption("dockerImage", options);
		// TODO check docker image format
		this.dockerImage = (image != "" ? image : defaultDockerImage());

		// Set the duration
		String duration = Utils.getOption("duration", options);
		this.duration = (duration != "" ? Integer.parseInt(duration) : defaultDuration());
	}

	/**
	 * Gets the current settings of the generator.
	 * 
	 * @return an array of strings suitable for passing to setOptions.
	 */
	@Override
	public String[] getOptions() {
		List<String> result = new ArrayList<>();
		result.addAll(Arrays.asList(super.getOptions()));

		result.addAll(Arrays.asList(
				"-dockerImage", dockerImage,
				"-duration", String.valueOf(duration)
				));
		return result.toArray(new String[0]);
	}

	/**
	 * Initializes the format for the data set produced. Must be called before the
	 * generateExample or generateExamples methods are used.
	 *
	 * Basically re-initializes the random number generator with the given seed.
	 * 
	 * @return the format for the data set
	 * @throws Exception if the generating of the format failed
	 * @see #getSeed()
	 */
	@Override
	public Instances defineDataFormat() throws Exception {
		ArrayList<Attribute> atts = new ArrayList<>(Arrays.asList(DATASET_ATTRIBUTES));
		m_DatasetFormat = new Instances(getRelationNameToUse(), atts, 0);
		return super.defineDataFormat();
	}

	/**
	 * Do nothing because the data set is already isn't generated one row at a time.
	 * (basically the generateExamples call the generateExample method
	 * several times to generate the data set, in our case the generateExamples
	 * will generate the data set without a unique and reproducible action)
	 * 
	 * @return null
	 * @throws Exception if the example could not be generated
	 */
	@Override
	public Instance generateExample() throws Exception {
		return null;
	}

	public void handlePacket(PacketData packet, Instances inst) {
		if(inst.size() >= this.getNumExamples()) return;

		// Create a new instance with the same format as the data set
		Instance instance = new DenseInstance(inst.numAttributes());
		instance.setDataset(getDatasetFormat());

		// Set the attributes values
		for (int i = 0; i < inst.numAttributes(); i++) {
			final Attribute entry = inst.attribute(i);
			String value = null;
			double numVal = 0;
			switch(entry.name()) {
			case "srcIp":
				value = packet.getSrcIP();
				break;
			case "dstIp":
				value = packet.getDstIP();
				break;
			case "type":
				value = packet.getType();
				break;
			case "headerChecksum":
				value = packet.getChecksum();
				break;
			case "protocol":
				numVal = packet.getProtocol();
				break;
			case "version":
				numVal = packet.getVersion();
				break;
			case "IHL":
				numVal = packet.getHeaderLength();
				break;
			case "length":
				numVal = packet.getTotalLength();
				break;
			case "identification":
				numVal = packet.getId();
				break;
			case "fragmentOffset":
				numVal = packet.getFragmentOffset();
				break;
			case "TTL":
				numVal = packet.getTTL();
				break;
			case "content":
				value = packet.getContentHex();
				break;
			case "timer":
				numVal = packet.getTimer() / 1000.;
				break;
			case "timestamp":
				numVal = packet.getTimestamp() / 1000.;
				break;
			default:
				throw new IllegalArgumentException("Error setting attribute '" + entry.name() + "' is unrecognized.");
			}
			if(value != null)
				instance.setValue(entry, value);
			else
				instance.setValue(entry, numVal);
		}

		inst.add(instance);
	}

	/**
	 * Generates a data set of network traffic.
	 * 
	 * (Look like our main function)
	 * 
	 * @return the generated data set
	 * @throws IOException 
	 * @throws InterruptedException 
	 * @throws IllegalStateException if the format of the data set is not defined
	 */
	@Override
	public Instances generateExamples() throws IllegalStateException, InterruptedException, IOException {
		System.out.println("Generating data set...");
		ConTacGenPacketHandler handler = ConTacGenPacketHandler.getInstance();

		// Check if the data set format is defined
		if (this.m_DatasetFormat == null) throw new IllegalStateException("Dataset format not defined.");

		// Start the docker container and run udpdos on it
		DockerRunner.dockerMain(dockerImage, (InetAddress t) -> {
			new UDPDos(t, this.m_Seed).run();
		}, this.duration);

		Instances result = new Instances(this.m_DatasetFormat, 0);
		handler.foreach((PacketData packet) -> handlePacket(packet, result)).clear();

		return result;
	}

	/**
	 * Generates a comment string that documents the data generator. By default
	 * this string is added at the beginning of the produced output as ARFF file
	 * type, next after the options.
	 * 
	 * @return string contains info about the generated rules
	 */
	@Override
	public String generateStart() throws Exception {
		//TODO
		return "prout";
	}

	/**
	 * Generates a comment string that documents the data generator. By default
	 * this string is added at the end of the produced output as ARFF file type.
	 * 
	 * @return string contains info about the generated rules
	 */
	@Override
	public String generateFinished() throws Exception {
		return "Wallahi Im finished";
	}

	/**
	 * I not understand what is this method for.
	 */
	@Override
	public boolean getSingleModeFlag() throws Exception {
		return false;
	}

	/**
	 * @return some form of version to define from which version this class existed. There are no logical or practical uses for this.
	 */
	@Override
	public String getRevision() {
		return "00000";
	}

	/**
	 * Main method for running this data generator.
	 * 
	 * @param args the command-line arguments
	 */
	public static void main(String[] args) {
		runDataGenerator(new ConTackGen(), args);
	}
}
