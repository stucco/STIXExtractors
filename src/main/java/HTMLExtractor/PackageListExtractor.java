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
import org.mitre.cybox.common_2.StringObjectPropertyType;
import org.mitre.cybox.common_2.StructuredTextType;
import org.mitre.cybox.objects.Hostname;
import org.mitre.cybox.objects.Product;
import org.mitre.cybox.cybox_2.RelatedObjectType;
import org.mitre.cybox.cybox_2.RelatedObjectsType;
import org.xml.sax.SAXException;			

public class PackageListExtractor extends HTMLExtractor	{
						
	private static final Logger logger = LoggerFactory.getLogger(PackageListExtractor.class);
	private static final String[] HEADERS = {"hostname", "package", "version"};
	private static final String HOSTNAME = "hostname";
	private static final String PACKAGE = "package";
	private static final String VERSION = "version";
	
	private STIXPackage stixPackage;

	public PackageListExtractor(String packageInfo)	{
		stixPackage = extract(packageInfo);
	}
					
	public STIXPackage getStixPackage() {
		return stixPackage;
	}

	private STIXPackage extract (String packageInfo)	{

		try	{

			CSVFormat csvFormat = CSVFormat.DEFAULT.withHeader(HEADERS);
			Reader reader = new StringReader(packageInfo);
			CSVParser csvParser = new CSVParser(reader, csvFormat);
			List<CSVRecord> records = csvParser.getRecords();
			
			if (records.size() == 0) return null;
			
			int start;
			CSVRecord record = records.get(0);
			if (record.get(0).equals(HOSTNAME))	{
				if (record.size() == 1) return null;
				else start = 1;
			}
			else start = 0;

			GregorianCalendar calendar = new GregorianCalendar();
			XMLGregorianCalendar now = DatatypeFactory.newInstance().newXMLGregorianCalendar(				
				new GregorianCalendar(TimeZone.getTimeZone("UTC")));
			stixPackage = new STIXPackage()				
 				.withSTIXHeader(new STIXHeaderType().
					withTitle("PackageList")) 
				.withTimestamp(now)
	 			.withId(new QName("gov.ornl.stucco", "PackageList-" + UUID.randomUUID().toString(), "stucco"));
			Observables observables = new Observables()
				.withCyboxMajorVersion("2.0")
				.withCyboxMinorVersion("1.0");

		 	for (int i = start; i < records.size(); i++)	{
			
				record = records.get(i);

				QName softwareId = new QName("gov.ornl.stucco", "software-" + UUID.randomUUID().toString(), "stucco");
				observables
					.withObservables(new Observable()	
						.withId(softwareId)
						.withTitle("Software")
						.withObservableSources(getMeasureSourceType("PackageList"))
						.withObject(new ObjectType()
							.withId(new QName("gov.ornl.stucco", "software-" + record.get(PACKAGE) + "_" + record.get(VERSION), "stucco"))
							.withDescription(new StructuredTextType()
								.withValue(record.get(PACKAGE) + " version " + record.get(VERSION)))
							.withProperties(new Product()
								.withProduct(new StringObjectPropertyType()
									.withValue(record.get(PACKAGE)))
								.withVersion(new StringObjectPropertyType()
									.withValue(record.get(VERSION))))));
				observables
					.withObservables(new Observable()	
						.withId(new QName("gov.ornl.stucco", "hostname-" + UUID.randomUUID().toString(), "stucco"))
						.withTitle("Hostname")
						.withObservableSources(getMeasureSourceType("PackageList"))
						.withObject(new ObjectType()
							.withId(new QName("gov.ornl.stucco", "hostname-" + record.get(HOSTNAME), "stucco"))
							.withDescription(new StructuredTextType()
								.withValue(record.get(HOSTNAME)))
							.withProperties(new Hostname()
								.withHostnameValue(new StringObjectPropertyType()
									.withValue(record.get(HOSTNAME))))
							.withRelatedObjects(new RelatedObjectsType()
								.withRelatedObjects(new RelatedObjectType()
									.withIdref(softwareId)
									.withRelationship(new ControlledVocabularyStringType()
										.withValue("host runs software"))))));
			
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
