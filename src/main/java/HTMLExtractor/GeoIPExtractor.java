package STIXExtractor;

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
import org.mitre.cybox.objects.CategoryTypeEnum;
import org.mitre.cybox.objects.Address;

import org.xml.sax.SAXException;			

public class GeoIPExtractor extends HTMLExtractor	{
						
	private static final Logger logger = LoggerFactory.getLogger(GeoIPExtractor.class);
	private static final String[] HEADERS = {"StartIP", "EndIP", "Start IP (int)", "End IP (int)", "Country code", "Country name"};
	private static final String STARTIP = "StartIP"; 
	private static final String ENDIP= "EndIP";
	private static final String STARTIPINT= "Start IP (int)";
	private static final String ENDIPINT= "End IP (int)";
	private static final String COUNTRYCODE= "Country code";	
	private static final String COUNTRYNAME= "Country name";
	
	private STIXPackage stixPackage;

	public GeoIPExtractor(String geoIpInfo)	{
		stixPackage = extract(geoIpInfo);
	}
					
	public STIXPackage getStixPackage() {
		return stixPackage;
	}

	private STIXPackage extract (String geoIpInfo)	{

		try	{
			GregorianCalendar calendar = new GregorianCalendar();
			XMLGregorianCalendar now = DatatypeFactory.newInstance().newXMLGregorianCalendar(				
				new GregorianCalendar(TimeZone.getTimeZone("UTC")));
			stixPackage = new STIXPackage()				
 				.withSTIXHeader(new STIXHeaderType().
					withTitle("Maxmind")) 
				.withTimestamp(now)
	 			.withId(new QName("gov.ornl.stucco", "Maxmind-" + UUID.randomUUID().toString(), "stucco"));
			Observables observables = new Observables()
				.withCyboxMajorVersion("2.0")
				.withCyboxMinorVersion("1.0");

			CSVFormat csvFormat = CSVFormat.DEFAULT.withHeader(HEADERS);
			Reader reader = new StringReader(geoIpInfo);
			CSVParser csvParser = new CSVParser(reader, csvFormat);
			List<CSVRecord> records = csvParser.getRecords();

			CSVRecord record = records.get(0);
			int start;
			if (record.get(0).equals(STARTIP))	start = 1;
			else start = 0;

		 	for (int i = start; i < records.size(); i++)	{
			
				record = records.get(i);

				observables
					.withObservables(new Observable()	
						.withId(new QName("gov.ornl.stucco", "addressRange-" + UUID.randomUUID().toString(), "stucco"))
						.withTitle("AddressRange")
						.withObservableSources(getMeasureSourceType("Maxmind"))
						.withObject(new ObjectType()
							.withId(new QName("gov.ornl.stucco", "addressRange-" + record.get(STARTIPINT) + "_" + record.get(ENDIPINT), "stucco"))
							.withLocation(new LocationType()
								.withId(new QName("gov.ornl.stucco", "countryCode-" + record.get(COUNTRYCODE), "stucco"))
								.withName(record.get(COUNTRYNAME)))
							.withDescription(new StructuredTextType()
								.withValue(record.get(STARTIP) + " through " + record.get(ENDIP)))
							.withProperties(new Address()
								.withAddressValue(new StringObjectPropertyType()
									.withValue(record.get(STARTIP) + " - " + record.get(ENDIP))
									.withCondition(ConditionTypeEnum.INCLUSIVE_BETWEEN)
									.withApplyCondition(ConditionApplicationEnum.ANY)
									.withDelimiter(" - "))
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
