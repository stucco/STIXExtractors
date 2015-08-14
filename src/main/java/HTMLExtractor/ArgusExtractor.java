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
	private static final String DEFAULT ="Default";
	private static String[] HEADERS = null;
	private static HashSet<String> headersSet = initHeadersSet();
	private static HashSet initHeadersSet() {
		headersSet = new HashSet<String>();
		headersSet.add(PROTOCOL);
		headersSet.add(SOURCE_ADDRESS);
		headersSet.add(SOURCE_PORT);
		headersSet.add(DESTINATION_ADDRESS);
		headersSet.add(DESTINATION_PORT);
		headersSet.add(STATE);
		headersSet.add(DEFAULT);

		return headersSet;
	}
	private STIXPackage stixPackage;

	public ArgusExtractor(String[] HEADERS, String argusInfo) {
		this.HEADERS = HEADERS;
		stixPackage = extract(argusInfo);
	}
					
	public STIXPackage getStixPackage() {
		return stixPackage;
	}

	private STIXPackage extract (String argusInfo) {
		try {
			stixPackage = initStixPackage("Argus");				
			Observables observables = initObservables();
			Observable srcIpObservable = null;
			Observable dstIpObservable = null;
			Observable srcPortObservable = null;
			Observable dstPortObservable = null;
			Observable srcAddressObservable = null;
			Observable dstAddressObservable = null;
			Observable flowObservable = null;
			List<CSVRecord> records = getCSVRecordsList(HEADERS, argusInfo);
							
		 	for (int i = 0; i < records.size(); i++) {
				CSVRecord record = records.get(i);
				String srcIp = null;
				String srcPort = null;
				String dstIp = null;
				String dstPort = null;
										
				if (!record.get(SOURCE_ADDRESS).isEmpty()) {
					srcIp = record.get(SOURCE_ADDRESS);
					srcIpObservable = setIpObservable(srcIp, "Argus");
					observables
						.withObservables(srcIpObservable);
				}
 				if (!record.get(SOURCE_PORT).isEmpty()) {
					srcPort = record.get(SOURCE_PORT);
					srcPortObservable = setPortObservable(srcPort, "Argus");
					observables
						.withObservables(srcPortObservable);
				}
				if (!record.get(DESTINATION_ADDRESS).isEmpty()) {
					dstIp = record.get(DESTINATION_ADDRESS);
					dstIpObservable = setIpObservable(dstIp, "Argus");
					observables
						.withObservables(dstIpObservable);
				}
				if (!record.get(DESTINATION_PORT).isEmpty()) {
					dstPort = record.get(DESTINATION_PORT);
					dstPortObservable = setPortObservable(dstPort, "Argus");
					observables
						.withObservables(dstPortObservable);
				}
				if (srcIp != null && srcPort != null) {
					srcAddressObservable = setAddressObservable(srcIp, srcIpObservable.getId(), srcPort, srcPortObservable.getId(), "Argus");
					observables
						.withObservables(srcAddressObservable);
				}
				if (dstIp != null && dstPort != null) {
					dstAddressObservable = setAddressObservable(dstIp, dstIpObservable.getId(), dstPort, dstPortObservable.getId(), "Argus");
					observables
						.withObservables(dstAddressObservable);
				}
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

					//if property is not among regular headers, adding it as a custom property
					for (int j = 0; j < HEADERS.length; j++) {
						if (headersSet.contains(HEADERS[j])) {
							continue;
						}
						properties
							.withProperties(new Property()		//list
								.withName(HEADERS[j])
									.withValue(record.get(HEADERS[j])));
					}
					if (!properties.getProperties().isEmpty()) {
						networkFlow
							.withCustomProperties(properties);
					}
					observables
						.withObservables(flowObservable
							.withObject(flowObject
								.withId(new QName("gov.ornl.stucco", "flow-" + srcIp + "_" + srcPort + "-" + dstIp + "_" + dstPort, "stucco"))
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
