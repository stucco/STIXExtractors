package STIXExtractor;

import java.util.List;
import java.util.ArrayList;
import java.util.UUID;

import java.io.IOException;

import org.apache.commons.csv.CSVRecord;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.namespace.QName;					

import org.mitre.stix.stix_1.STIXPackage;
import org.mitre.cybox.cybox_2.Observables;
import org.mitre.cybox.cybox_2.Observable;
import org.mitre.cybox.cybox_2.ObservableCompositionType;
import org.mitre.cybox.cybox_2.OperatorTypeEnum;
import org.mitre.cybox.cybox_2.ObjectType;
import org.mitre.cybox.cybox_2.RelatedObjectsType;
import org.mitre.cybox.cybox_2.RelatedObjectType;
import org.mitre.cybox.common_2.CustomPropertiesType;
import org.mitre.cybox.common_2.Property;
import org.mitre.cybox.common_2.ControlledVocabularyStringType;
import org.mitre.cybox.common_2.StringObjectPropertyType;
import org.mitre.cybox.common_2.StructuredTextType;
import org.mitre.cybox.common_2.UnsignedIntegerObjectPropertyType;
import org.mitre.cybox.objects.CategoryTypeEnum;
import org.mitre.cybox.objects.Address;
import org.mitre.cybox.objects.Hostname;
import org.mitre.cybox.objects.ArgumentListType;
import org.mitre.cybox.objects.ProcessObjectType;
import org.mitre.cybox.objects.Product;
import org.mitre.cybox.objects.UserAccountObjectType;
import org.mitre.cybox.objects.SocketAddress;
import org.mitre.cybox.objects.NetworkFlowObject;
import org.mitre.cybox.objects.NetworkFlowLabelType;

import org.xml.sax.SAXException;			

/**
 * Hone data to STIX format extractor.
 *
 * @author Maria Vincent
 */
public class HoneExtractor extends HTMLExtractor {
						
	private static final Logger logger = LoggerFactory.getLogger(HoneExtractor.class);
	private static String[] HEADERS = {"user", "uid", "proc_pid", "proc_ppid", "path", "argv", "conn_id", "timestamp_epoch_ms", 
					"source_port", "dest_port", "ip_version", "source_ip", "dest_ip", "byte_cnt", "packet_cnt"};
	private static String USER = "user";
	private static String UID = "uid";
	private static String PROC_PID = "proc_pid";
	private static String PROC_PPID = "proc_ppid";
	private static String PATH = "path";
	private static String ARGV = "argv";
	private static String CONN_ID = "conn_id";
	private static String TIMESTAMP_EPOCH_MS = "timestamp_epoch_ms"; 
	private static String SOURCE_PORT = "source_port";
	private static String DEST_PORT = "dest_port";
	private static String IP_VERSION = "ip_version";
	private static String SOURCE_IP = "source_ip";
	private static String DEST_IP = "dest_ip";
	private static String BYTE_CNT = "byte_cnt";
	private static String PACKET_CNT = "packet_cnt";
	private static String HOSTNAME = null;

	private STIXPackage stixPackage;

	//if hostname is not given
	public HoneExtractor(String honeInfo) {
		stixPackage = extract(honeInfo);
	}
	public HoneExtractor(String honeInfo, String hostname) {
		this.HOSTNAME = hostname;
		stixPackage = extract(honeInfo);
	}
					
	public STIXPackage getStixPackage() {
		return stixPackage;
	}

	private STIXPackage extract (String honeInfo) {
		try	{
			List<CSVRecord> records = getCSVRecordsList(HEADERS, honeInfo); 

			if (records.size() == 0) {
				return null;
			}
			
			CSVRecord record = records.get(0);
			int start;
			if (record.get(0).equals(USER))	{
				if (record.size() == 1) {
					return null;
				} else {
					start = 1;
				}
			} else {
				start = 0;
			}

			stixPackage = initStixPackage("Hone");
			Observables observables = initObservables();

		 	for (int i = start; i < records.size(); i++)	{
			
				record = records.get(i);

				Observable hostnameObservable = null;
				Observable softwareObservable = null;
				Observable srcAddressObservable = null;
				Observable dstAddressObservable = null;
				Observable srcIpObservable = null;
				Observable dstIpObservable = null;
				Observable srcPortObservable = null;
				Observable dstPortObservable = null;
				Observable accountObservable = null;
				Observable flowObservable = null;

				/* host */
				if (HOSTNAME != null) {	
					hostnameObservable = setHostObservable(HOSTNAME, "Hone");
				}
				
				/* software */
				if (!record.get(PATH).isEmpty()) {

					//processing process info
					ProcessObjectType process = new ProcessObjectType()
						.withName(new StringObjectPropertyType()	//path as process name
							.withValue(record.get(PATH)));

					if (!record.get(PROC_PID).isEmpty()) {
						process
							.withPID(new UnsignedIntegerObjectPropertyType() 
								.withValue(record.get(PROC_PID)));
					}

					if (!record.get(PROC_PPID).isEmpty()) {
						process
							.withParentPID(new UnsignedIntegerObjectPropertyType() 
								.withValue(record.get(PROC_PPID)));
					}

					if (!record.get(ARGV).isEmpty()) {
						ArgumentListType argvs = new ArgumentListType();
						String[] argvArray = record.get(ARGV).split(" ");

						for (int j = 0; j < argvArray.length; j++) {
							argvs
								.withArguments(new StringObjectPropertyType()
									.withValue(argvArray[j]));
						}	
						
						if (!argvs.getArguments().isEmpty()) {
							process
								.withArgumentList(argvs);
						}
					}

					softwareObservable = new Observable()	
						.withId(new QName("gov.ornl.stucco", "software-" + UUID.randomUUID().toString(), "stucco"))
							.withTitle("Software")
							.withObservableSources(getMeasureSourceType("Hone"))
							.withObservableComposition(new ObservableCompositionType()
								.withOperator(OperatorTypeEnum.AND)
								.withObservables(new Observable()
									.withObject(new ObjectType()
										.withId(new QName("gov.ornl.stucco", "software-" + record.get(PATH).replaceAll("/", "_"), "stucco"))
										.withDescription(new StructuredTextType()
											.withValue(record.get(PATH)))
										.withProperties(new Product()
											.withProduct(new StringObjectPropertyType()
												.withValue(record.get(PATH))))))
								.withObservables(new Observable()
									.withObject(new ObjectType()
										.withProperties(process))));
				}

				/* source IP */
				if (!record.get(SOURCE_IP).isEmpty()) {
					observables
						.withObservables(srcIpObservable = setIpObservable(record.get(SOURCE_IP), "Hone"));
				}

				/* destination IP */
				if (!record.get(DEST_IP).isEmpty()) {
					observables
						.withObservables(dstIpObservable = setIpObservable(record.get(DEST_IP), "Hone"));
				}

				/* source Port */
				if (!record.get(SOURCE_PORT).isEmpty()) {
					observables
						.withObservables(srcPortObservable = setPortObservable(record.get(SOURCE_PORT), "Hone"));
				}
				
				/* destination Port */
				if (!record.get(DEST_PORT).isEmpty()) {
					observables
						.withObservables(dstPortObservable = setPortObservable(record.get(DEST_PORT), "Hone"));
				}

				/* source address -> source IP, source address -> source Port */
				if (!record.get(SOURCE_IP).isEmpty() && !record.get(SOURCE_PORT).isEmpty()) {
					observables
						.withObservables(srcAddressObservable = getAddressObservable (record.get(SOURCE_IP), srcIpObservable.getId(), 
									record.get(SOURCE_PORT), srcPortObservable.getId(), "Hone"));
				}

				/* destination address -> destination IP, destination address -> destination Port */
				if (!record.get(DEST_IP).isEmpty() && !record.get(DEST_PORT).isEmpty()) {
					observables
						.withObservables(dstAddressObservable = getAddressObservable (record.get(DEST_IP), dstIpObservable.getId(), 
									record.get(DEST_PORT), dstPortObservable.getId(), "Hone"));
				}

				//flow, flow -> dstAddress, flow -> srdAddress
				if (!record.get(DEST_IP).isEmpty() && !record.get(DEST_PORT).isEmpty() &&
					!record.get(SOURCE_IP).isEmpty() && !record.get(SOURCE_PORT).isEmpty())	{	
					flowObservable =  initFlowObservable("Hone")
						.withObject(new ObjectType()
							.withId(new QName("gov.ornl.stucco", "flow-" + ipToLong(record.get(SOURCE_IP)) + "_" +record.get(SOURCE_PORT) + "-" + 
								ipToLong(record.get(DEST_IP)) + "_" + record.get(DEST_PORT), "stucco"))
							.withDescription(new org.mitre.cybox.common_2.StructuredTextType()
								.withValue(record.get(SOURCE_IP) + ", port " +record.get(SOURCE_PORT) + " to " + 
									record.get(DEST_IP) + ", port " + record.get(DEST_PORT)))
							.withProperties(new NetworkFlowObject()
								.withNetworkFlowLabel(new NetworkFlowLabelType()
									.withSrcSocketAddress(new SocketAddress()
										.withObjectReference(srcAddressObservable.getId()))
									.withDestSocketAddress(new SocketAddress()
										.withObjectReference(dstAddressObservable.getId())))));

					CustomPropertiesType properties = new CustomPropertiesType();
					if (!record.get(TIMESTAMP_EPOCH_MS).isEmpty()) {
						properties
							.withProperties(new Property() 	
								.withName("Start_Time")
								.withValue(record.get(TIMESTAMP_EPOCH_MS)));
					}

					if (!record.get(BYTE_CNT).isEmpty()) {
						properties
							.withProperties(new Property() 	
								.withName("Total_Bytes")
								.withValue(record.get(BYTE_CNT)));
					}

					if (!record.get(PACKET_CNT).isEmpty()) {
						properties
							.withProperties(new Property() 	
								.withName("Total_Packets")
								.withValue(record.get(PACKET_CNT)));
					}

					if (!properties.getProperties().isEmpty()) {
						flowObservable
							.getObject()
								.getProperties()
									.withCustomProperties(properties);
					}

					observables
						.withObservables(flowObservable);
				}

				/* account */
				if (HOSTNAME != null && !record.get(UID).isEmpty()) {	
					observables	
						.withObservables( accountObservable = new Observable()	
							.withId(new QName("gov.ornl.stucco", "account-" + UUID.randomUUID().toString(), "stucco"))
							.withTitle("Account")
							.withObservableSources(getMeasureSourceType("Hone"))
							.withObject(new ObjectType()
								.withId(new QName("gov.ornl.stucco", "account-" + HOSTNAME + "_" + record.get(UID), "stucco"))
								.withDescription(new StructuredTextType()
									.withValue("uid " + record.get(UID) + " on host " + HOSTNAME))
								.withProperties(new UserAccountObjectType()
									.withUsername(new StringObjectPropertyType()
										.withValue(record.get(UID)))
									.withFullName(new StringObjectPropertyType()
										.withValue(record.get(USER))))));
				}
				
				if (hostnameObservable != null)	{

					/* host -> software relation */	
					List<RelatedObjectType> relatedObjects = new ArrayList<RelatedObjectType>();
					if (softwareObservable != null)	{
						relatedObjects.add(
							setRelatedObject(softwareObservable.getId(), "runs", 
								HOSTNAME + " runs " + record.get(PATH), "Hone"));
					}

					/* host -> source address relation */
					if (srcAddressObservable != null) {
						relatedObjects.add(	
							setRelatedObject(srcAddressObservable.getId(), "usesAddress", 			
								HOSTNAME + " uses address " + record.get(SOURCE_IP) + ", port " + record.get(SOURCE_PORT), "Hone"));
					}

					//if relations exist, adding them to the hostname observable
					if (!relatedObjects.isEmpty()) {
						hostnameObservable
							.getObject()
								.withRelatedObjects(new RelatedObjectsType()
									.withRelatedObjects(relatedObjects));
					}
					observables
						.withObservables(hostnameObservable);
				}

				if (softwareObservable != null)	{

					/* software -> flow relation */
					List<RelatedObjectType> relatedObjects = new ArrayList<RelatedObjectType>();
					if (flowObservable != null) {
						relatedObjects.add(
							setRelatedObject(flowObservable.getId(), "hasFlow",
								record.get(PATH) + " has flow " + record.get(SOURCE_IP) + ", port " + record.get(SOURCE_PORT) +" to " + 
									record.get(DEST_IP) + ", port " + record.get(DEST_PORT), "Hone"));
					}

					/* software -> account relation */
					if (accountObservable != null) {
						relatedObjects.add(
							setRelatedObject(accountObservable.getId(), "runsAs",
								record.get(PATH) + " runs as uid " + record.get(UID) + " on host " + HOSTNAME, "Hone"));	
					}

					//if relations exist, adding them to the software observable
					if (!relatedObjects.isEmpty()) {
						softwareObservable
							.getObservableComposition()
								.getObservables().get(0)
									.getObject()
										.withRelatedObjects(new RelatedObjectsType()
											.withRelatedObjects(relatedObjects));
					}
					
					observables
						.withObservables(softwareObservable);
				}
			}

			return (observables.getObservables().isEmpty()) ? null : stixPackage.withObservables(observables);

		} catch (DatatypeConfigurationException e)	{
			e.printStackTrace();
		} catch (IOException e)	{
			e.printStackTrace();
		}

		return null;
	}
}
