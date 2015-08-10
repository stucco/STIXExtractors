package STIXExtractor;

import java.util.List;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.TimeZone;
import java.util.UUID;

import java.io.Reader;
import java.io.StringReader;
import java.io.IOException;

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
import org.mitre.cybox.cybox_2.Observable;
import org.mitre.cybox.cybox_2.ObjectType;
import org.mitre.cybox.common_2.Property;
import org.mitre.cybox.common_2.ControlledVocabularyStringType;
import org.mitre.cybox.common_2.DatatypeEnum;
import org.mitre.cybox.common_2.StringObjectPropertyType;
import org.mitre.cybox.common_2.ConditionTypeEnum;
import org.mitre.cybox.common_2.ConditionApplicationEnum;
import org.mitre.cybox.common_2.StructuredTextType;
import org.mitre.cybox.common_2.LocationType;
import org.mitre.cybox.cybox_2.KeywordsType;
import org.mitre.cybox.objects.CategoryTypeEnum;
import org.mitre.cybox.objects.Address;

import org.xml.sax.SAXException;			

public class CIFEmergingThreatsExtractor extends HTMLExtractor	{
						
	private static final Logger logger = LoggerFactory.getLogger(CIFEmergingThreatsExtractor.class);
	private static final String[] HEADERS = {"ip"};
	private static final String IP = "ip";
	
	private STIXPackage stixPackage;

	public CIFEmergingThreatsExtractor(String cifInfo)	{
		stixPackage = extract(cifInfo);
	}
					
	private long ipToLong(String ipString)	{

		long ipLong = 0, ip;
		String[] ipArray = ipString.split("\\.");

		for (int i = 3; i >= 0; i--) {
			ip = Long.parseLong(ipArray[3 - i]);
			ipLong |= ip << (i * 8);

		}

		return ipLong;
	}

	public STIXPackage getStixPackage() {
		return stixPackage;
	}

	private STIXPackage extract (String cifInfo)	{

		try	{

			CSVFormat csvFormat = CSVFormat.DEFAULT.withHeader(HEADERS);
			Reader reader = new StringReader(cifInfo);
			CSVParser csvParser = new CSVParser(reader, csvFormat);
			List<CSVRecord> records = csvParser.getRecords();
			
			if (records.size() == 0) return null;
			
			int start;
			CSVRecord record = records.get(0);
			if (record.get(0).equals(IP))	{
				if (record.size() == 1) return null;
				else start = 1;
			}
			else start = 0;

			GregorianCalendar calendar = new GregorianCalendar();
			XMLGregorianCalendar now = DatatypeFactory.newInstance().newXMLGregorianCalendar(				
				new GregorianCalendar(TimeZone.getTimeZone("UTC")));
			stixPackage = new STIXPackage()				
 				.withSTIXHeader(new STIXHeaderType().
					withTitle("CIF Emerging Threats Extractor")) 
				.withTimestamp(now)
	 			.withId(new QName("gov.ornl.stucco", "cifemergingthreatsextractor-" + UUID.randomUUID().toString(), "stucco"));
			Observables observables = new Observables()
				.withCyboxMajorVersion("2.0")
				.withCyboxMinorVersion("1.0");

		 	for (int i = start; i < records.size(); i++)	{
			
				record = records.get(i);

				observables
					.withObservables(new Observable()	
						.withId(new QName("gov.ornl.stucco", "ip-" + UUID.randomUUID().toString(), "stucco"))
						.withTitle("IP")
						.withObservableSources(getMeasureSourceType("rules.emergingthreats.net"))
						.withKeywords(new KeywordsType()
							.withKeywords("Malware"))
						.withObject(new ObjectType()
							.withId(new QName("gov.ornl.stucco", "ip-" + ipToLong(record.get(IP)), "stucco"))
							.withDescription(new StructuredTextType()
								.withValue(record.get(IP)))
							.withProperties(new Address()
								.withAddressValue(new StringObjectPropertyType()
									.withValue(record.get(IP)))
								.withCategory(CategoryTypeEnum.IPV_4_ADDR))));
				
		
			}
				
			stixPackage
				.withObservables(observables);

		} catch (DatatypeConfigurationException e)	{
			e.printStackTrace();
		} 
		catch (IOException e)	{
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
