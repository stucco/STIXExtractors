package STIXExtractor;

import java.util.EnumMap;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Map;
import java.util.HashMap;
import java.util.List;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.TimeZone;
import java.util.UUID;

import java.io.Reader;
import java.io.StringReader;
import java.io.IOException;

import java.text.*;

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVRecord;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.namespace.QName;					
import javax.xml.parsers.ParserConfigurationException;

import org.mitre.stix.stix_1.STIXPackage;
import org.mitre.stix.stix_1.STIXHeaderType;
import org.mitre.cybox.cybox_2.Observables;
import org.mitre.cybox.cybox_2.Observables;
import org.mitre.cybox.cybox_2.Observable;
import org.mitre.cybox.cybox_2.ObjectType;
import org.mitre.cybox.objects.NetworkFlowObject;
import org.mitre.cybox.objects.NetworkFlowLabelType;
import org.mitre.cybox.objects.IANAAssignedIPNumbersType;
import org.mitre.cybox.objects.IANAAssignedIPNumbersTypeEnum;
import org.mitre.cybox.common_2.CustomPropertiesType;
import org.mitre.cybox.common_2.Property;
import org.mitre.cybox.common_2.ControlledVocabularyStringType;
import org.mitre.cybox.common_2.DatatypeEnum;
import org.mitre.cybox.objects.CategoryTypeEnum;
import org.mitre.cybox.cybox_2.RelatedObjectsType;
import org.mitre.cybox.objects.SocketAddress;
import org.mitre.cybox.common_2.StringObjectPropertyType;
import org.mitre.cybox.objects.Address;
import org.mitre.cybox.common_2.PositiveIntegerObjectPropertyType;
import org.mitre.cybox.objects.Port;

import org.xml.sax.SAXException;			

public class ArgusExtractor extends HTMLExtractor	{
						
	private static final Logger logger = LoggerFactory.getLogger(ArgusExtractor.class);
	private static String[] HEADERS = null;
	private STIXPackage stixPackage;

	private enum HeadersEnum {
		PROTOCOL("Proto"),
		SOURCE_ADDRESS("SrcAddr"),
		SOURCE_PORT("Sport"),
		DESTINATION_ADDRESS("DstAddr"),
		DESTINATION_PORT("Dport"),
		STATE("State"),
		DEFAULT("Default");

		private String value;

		HeadersEnum (String value)	{
			this.value = value;
		}
		
		public static HeadersEnum fromValue(String value)	{
			for (HeadersEnum he : HeadersEnum.values())	{
				if (he.value.equals(value))	return he;
			}
			return HeadersEnum.DEFAULT;
		}
	}
										
	public ArgusExtractor(String[] HEADERS, String argusInfo)	{
		this.HEADERS = HEADERS;
		stixPackage = extract(argusInfo);
	}
					
	public STIXPackage getStixPackage() {
		return stixPackage;
	}

	private STIXPackage extract (String argusInfo)	{

		try	{
			GregorianCalendar calendar = new GregorianCalendar();
			XMLGregorianCalendar now = DatatypeFactory.newInstance().newXMLGregorianCalendar(				
				new GregorianCalendar(TimeZone.getTimeZone("UTC")));
			stixPackage = new STIXPackage()				
 				.withSTIXHeader(new STIXHeaderType().
					withTitle("Argus")) 
				.withTimestamp(now)
	 			.withId(new QName("gov.ornl.stucco", "Argus-" + UUID.randomUUID().toString(), "stucco"));
			Observables observables = new Observables()
				.withCyboxMajorVersion("2.0")
				.withCyboxMinorVersion("1.0");
			CSVFormat csvFormat = CSVFormat.DEFAULT.withHeader(HEADERS);
			Reader reader = new StringReader(argusInfo);
			CSVParser csvParser = new CSVParser(reader, csvFormat);
			List<CSVRecord> records = csvParser.getRecords();

		 	for (int i = 0; i < records.size(); i++)	{
			
				CSVRecord record = records.get(i);
				QName flowId = new QName("gov.ornl.stucco", "flow-" + UUID.randomUUID().toString(), "stucco");
				Observable flowObservable = new Observable()	
					.withId(flowId)
					.withTitle("Flow")
					.withObservableSources(getMeasureSourceType("Argus"));
				ObjectType flowObject = new ObjectType();
				NetworkFlowLabelType networkLabel = new NetworkFlowLabelType();
				CustomPropertiesType properties = new CustomPropertiesType();
				String srcIp = null, srcPort = null, dstIp = null, dstPort = null;

				String id = record.get(HeadersEnum.SOURCE_ADDRESS.value) + "-" + record.get(HeadersEnum.SOURCE_PORT.value) + "-" +
						record.get(HeadersEnum.DESTINATION_ADDRESS.value) + "-" + record.get(HeadersEnum.DESTINATION_PORT.value); 
				String description = record.get(HeadersEnum.SOURCE_ADDRESS.value) + ", port " + record.get(HeadersEnum.SOURCE_PORT.value) + " to " +
						record.get(HeadersEnum.DESTINATION_ADDRESS.value) + ", port " + record.get(HeadersEnum.DESTINATION_PORT.value); 
				
				for (int j = 0; j < HEADERS.length; j++) {	

					switch (HeadersEnum.fromValue(HEADERS[j]))	{

						case PROTOCOL:		networkLabel
										.withIPProtocol(new IANAAssignedIPNumbersType()
											.withValue(record.get(HEADERS[j])));
									break;
						case SOURCE_ADDRESS:	srcIp = record.get(HEADERS[j]);
									break;
						case SOURCE_PORT:	srcPort = record.get(HEADERS[j]);
									break;
						case DESTINATION_ADDRESS:	dstIp = record.get(HEADERS[j]);
									break;
						case DESTINATION_PORT:	dstPort = record.get(HEADERS[j]);
									break;
						case STATE:		flowObject
										.withState(new ControlledVocabularyStringType()
											.withValue(record.get(HEADERS[j])));
									break;
						case DEFAULT:		properties
										.withProperties(new Property()		//list
											.withName(HEADERS[j])
											.withValue(record.get(HEADERS[j])));
									break;
					}
				}
					
				Observable srcIpObservable = getIpObservable("Argus", srcIp, CategoryTypeEnum.IPV_4_ADDR);
				Observable dstIpObservable = getIpObservable("Argus", dstIp, CategoryTypeEnum.IPV_4_ADDR);
				Observable srcPortObservable = getPortObservable("Argus", srcPort);
				Observable dstPortObservable = getPortObservable("Argus", dstPort);
				
				QName srcIpId = srcIpObservable.getId();
				QName dstIpId = dstIpObservable.getId();
				QName srcPortId = srcPortObservable.getId();
				QName dstPortId = dstPortObservable.getId();

				Observable srcAddressObservable = getAddressObservable("Argus", srcIp, srcIpId, srcPort, srcPortId);
				Observable dstAddressObservable = getAddressObservable("Argus", dstIp, dstIpId, dstPort, dstPortId);
				
				QName srcAddressId = srcAddressObservable.getId();
				QName dstAddressId = dstAddressObservable.getId();
				
				observables
					.withObservables(srcAddressObservable)
					.withObservables(dstAddressObservable)
					.withObservables(srcIpObservable)
					.withObservables(dstIpObservable)
					.withObservables(srcPortObservable)
					.withObservables(dstPortObservable)
					.withObservables(flowObservable
						.withObject(flowObject
							.withId(new QName("gov.ornl.stucco", "flow-" + id, "stucco"))
							.withDescription(new org.mitre.cybox.common_2.StructuredTextType()
								.withValue(description))
							.withProperties(new NetworkFlowObject()
								.withNetworkFlowLabel(networkLabel
									.withSrcSocketAddress(new SocketAddress()
										.withObjectReference(srcAddressId))
									.withDestSocketAddress(new SocketAddress()
										.withObjectReference(dstAddressId)))
								.withCustomProperties(properties))));
			}
				
			stixPackage
				.withObservables(observables);

		} catch (DatatypeConfigurationException e)	{
			e.printStackTrace();
		} catch (IOException e)	{
			e.printStackTrace();
		}

		return stixPackage;
	}
	
	boolean validate(STIXPackage stixPackage) {
		
		try	{
			return stixPackage.validate();
		}			
		catch (SAXException e)	{
			e.printStackTrace();
		}
		return false;
	}
}
