package STIXExtractor;

import java.util.HashSet;
import java.util.List;

import java.io.IOException;

import javax.xml.namespace.QName;
import javax.xml.datatype.DatatypeConfigurationException;

import org.apache.commons.csv.CSVRecord;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.mitre.stix.stix_1.STIXPackage;
import org.mitre.cybox.cybox_2.Observables;
import org.mitre.cybox.cybox_2.Observable;
import org.mitre.cybox.cybox_2.ObjectType;
import org.mitre.cybox.common_2.Property;
import org.mitre.cybox.common_2.ControlledVocabularyStringType;
import org.mitre.cybox.common_2.CustomPropertiesType;
import org.mitre.cybox.objects.SocketAddress;
import org.mitre.cybox.objects.NetworkFlowObject;
import org.mitre.cybox.objects.NetworkFlowLabelType;
import org.mitre.cybox.objects.IANAAssignedIPNumbersType;

/**
 * Argus data to STIX format extractor.
 *
 * @author Maria Vincent
 */
public class ArgusExtractor extends HTMLExtractor {
						
	private static final Logger logger = LoggerFactory.getLogger(ArgusExtractor.class);
	private static final String PROTOCOL ="Proto";
	private static final String SOURCE_ADDRESS ="SrcAddr";
	private static final String SOURCE_PORT = "Sport";
	private static final String DESTINATION_ADDRESS ="DstAddr";
	private static final String DESTINATION_PORT ="Dport";
	private static final String STATE ="State";
	private static String[] HEADERS = null;
	private STIXPackage stixPackage;
	private HashSet<String> headersSet;
	
	public ArgusExtractor(String[] HEADERS, String argusInfo) {
		this.HEADERS = HEADERS;
		initHeadersSet();
		stixPackage = extract(argusInfo);
	}
					
	public STIXPackage getStixPackage() {
		return stixPackage;
	}

	/* making a set of headers that would go into custom fields */
	private void initHeadersSet() {
		headersSet = new HashSet<String>();		
		
		for (int i = 0; i < HEADERS.length; i++) {
			headersSet.add(HEADERS[i]);
		}
		
		headersSet.remove(PROTOCOL);
		headersSet.remove(SOURCE_ADDRESS);
		headersSet.remove(SOURCE_PORT);
		headersSet.remove(DESTINATION_ADDRESS);
		headersSet.remove(DESTINATION_PORT);
		headersSet.remove(STATE);
	}

	private STIXPackage extract (String argusInfo) {
		try {
			stixPackage = initStixPackage("Argus");				
			Observables observables = initObservables();
			List<CSVRecord> records = getCSVRecordsList(HEADERS, argusInfo);
			
			if (records.isEmpty()) {
				return null;
			}
							
		 	for (int i = 0; i < records.size(); i++) {
				CSVRecord record = records.get(i);
				Observable srcIpObservable = null;
				Observable dstIpObservable = null;
				Observable srcPortObservable = null;
				Observable dstPortObservable = null;
				Observable srcAddressObservable = null;
				Observable dstAddressObservable = null;
				Observable flowObservable = null;
				String srcIp = null;
				String srcPort = null;
				String dstIp = null;
				String dstPort = null;
				long srcIpInt = 0;
				long dstIpInt = 0;
							
				/* source ip */			
				if (!record.get(SOURCE_ADDRESS).isEmpty()) {
					srcIp = record.get(SOURCE_ADDRESS);
					srcIpInt = ipToLong(srcIp);
					srcIpObservable = setIpObservable(srcIp, srcIpInt, "Argus");
					observables
						.withObservables(srcIpObservable);
				}

				/* source port */
 				if (!record.get(SOURCE_PORT).isEmpty()) {
					srcPort = record.get(SOURCE_PORT);
					srcPortObservable = setPortObservable(srcPort, "Argus");
					observables
						.withObservables(srcPortObservable);
				}

				/* destination ip */
				if (!record.get(DESTINATION_ADDRESS).isEmpty()) {
					dstIp = record.get(DESTINATION_ADDRESS);
					dstIpInt = ipToLong(dstIp);
					dstIpObservable = setIpObservable(dstIp, dstIpInt, "Argus");
					observables
						.withObservables(dstIpObservable);
				}

				/* destination port */
				if (!record.get(DESTINATION_PORT).isEmpty()) {
					dstPort = record.get(DESTINATION_PORT);
					dstPortObservable = setPortObservable(dstPort, "Argus");
					observables
						.withObservables(dstPortObservable);
				}

				/* source address */
				if (srcIp != null && srcPort != null) {
					srcAddressObservable = setAddressObservable(srcIp, srcIpInt, srcIpObservable.getId(), srcPort, srcPortObservable.getId(), "Argus");
					observables
						.withObservables(srcAddressObservable);
				}

				/* destination address */
				if (dstIp != null && dstPort != null) {
					dstAddressObservable = setAddressObservable(dstIp, dstIpInt, dstIpObservable.getId(), dstPort, dstPortObservable.getId(), "Argus");
					observables
						.withObservables(dstAddressObservable);
				}

				/* flow */
				if (srcIp != null && srcPort != null && dstIp != null && dstPort != null) {
					flowObservable = initFlowObservable("Argus");	
					ObjectType flowObject = new ObjectType();
					NetworkFlowObject networkFlow = new NetworkFlowObject();
					NetworkFlowLabelType networkLabel = new NetworkFlowLabelType();
					CustomPropertiesType properties = new CustomPropertiesType();

					if (!record.get(PROTOCOL).isEmpty()) {
						networkLabel
							.withIPProtocol(new IANAAssignedIPNumbersType()
								.withValue(record.get(PROTOCOL)));
					}
					if (!record.get(STATE).isEmpty()) {
						flowObject
							.withState(new ControlledVocabularyStringType()
								.withValue(record.get(STATE)));
					}		

					//adding custom fields
					for (String property : headersSet) {
						if (!record.get(property).isEmpty()) {
							properties
								.withProperties(new Property()	
									.withName(property)
										.withValue(record.get(property)));
						}
					}
					if (!properties.getProperties().isEmpty()) {
						networkFlow
							.withCustomProperties(properties);
					}

					observables
						.withObservables(flowObservable
							.withObject(flowObject
								.withId(new QName("gov.ornl.stucco", "flow-" + srcIpInt + "_" + srcPort + "-" 
													     + dstIpInt + "_" + dstPort, "stucco"))
								.withDescription(new org.mitre.cybox.common_2.StructuredTextType()
									.withValue(srcIp + ", port " + srcPort + " to " + dstIp + ", port " + dstPort))
								.withProperties(networkFlow
									.withNetworkFlowLabel(networkLabel
										.withSrcSocketAddress(new SocketAddress()
											.withObjectReference(srcAddressObservable.getId()))
										.withDestSocketAddress(new SocketAddress()
											.withObjectReference(dstAddressObservable.getId()))))));
				}
			}
			
			return (!observables.getObservables().isEmpty()) ? stixPackage.withObservables(observables) : null;	

		} catch (DatatypeConfigurationException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}

		return null;
	}
}
