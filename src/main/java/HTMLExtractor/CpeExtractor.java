package STIXExtractor;

import java.util.List;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.TimeZone;
import java.util.UUID;

import org.jsoup.Jsoup;
import org.jsoup.parser.Parser;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import java.text.*;

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
import org.mitre.cybox.common_2.StringObjectPropertyType;
import org.mitre.cybox.common_2.StructuredTextType;
import org.mitre.cybox.common_2.CustomPropertiesType;
import org.mitre.cybox.objects.Product;

import org.xml.sax.SAXException;			

public class CpeExtractor extends HTMLExtractor	{
						
	private static final Logger logger = LoggerFactory.getLogger(CpeExtractor.class);
	
	private STIXPackage stixPackage;

	public CpeExtractor(String cpeInfo)	{
		extract(cpeInfo);
	}
					
	public STIXPackage getStixPackage() {
		return stixPackage;
	}

	private STIXPackage extract (String cpeInfo)	{

		try	{
			Document doc = Jsoup.parse(cpeInfo);
			Elements entries = doc.select("cpe-item");

			if (entries.size() == 0) return stixPackage = null;
			
			GregorianCalendar calendar = new GregorianCalendar();
			XMLGregorianCalendar now = DatatypeFactory.newInstance().newXMLGregorianCalendar(				
				new GregorianCalendar(TimeZone.getTimeZone("UTC")));
			stixPackage = new STIXPackage()				
 				.withSTIXHeader(new STIXHeaderType().
					withTitle("CPE")) 
				.withTimestamp(now)
	 			.withId(new QName("gov.ornl.stucco", "CPE-" + UUID.randomUUID().toString(), "stucco"));
			Observables observables = new Observables()
				.withCyboxMajorVersion("2.0")
				.withCyboxMinorVersion("1.0");

			for (Element entry : entries)	{	
		
				Product product = new Product();
				String[] cpe = entry.attr("name").split(":");
		
				for (int i = 1; i < cpe.length; i++)	{
					if (cpe[i].isEmpty()) continue;

					switch (i)	{
						case 1:	product
								.withCustomProperties(new CustomPropertiesType()
									.withProperties(new Property()
										.withName("Part")
										.withValue(cpe[1])));
							break;
						case 2:	product
								.withVendor(new StringObjectPropertyType()
									.withValue(cpe[2]));
							break;
						case 3:	product
								.withProduct(new StringObjectPropertyType()
									.withValue(cpe[3]));
							break;
						case 4:	product
								.withVersion(new StringObjectPropertyType()
									.withValue(cpe[4]));
							break;
						case 5:	product 
								.withUpdate(new StringObjectPropertyType()
									.withValue(cpe[5]));
							break;
						case 6:	product
								.withEdition(new StringObjectPropertyType()
									.withValue(cpe[6]));
							break;
						case 7:	product
								.withLanguage(new StringObjectPropertyType()
									.withValue(cpe[7]));
							break;
					}
				}		
			
				//software
				observables
					.withObservables(new Observable()	
						.withId(new QName("gov.ornl.stucco", "cpe-" + UUID.randomUUID().toString(), "stucco"))
						.withTitle("Software")
						.withObservableSources(getMeasureSourceType("CPE"))
						.withObject(new ObjectType()
							.withId(new QName("gov.ornl.stucco", "software-" + entry.attr("name"), "stucco"))
							.withDescription(new StructuredTextType()
								.withValue(entry.select("title[xml:lang=en-US]").text()))
							.withProperties(product)));
			}

			stixPackage
				.withObservables(observables);

		} catch (DatatypeConfigurationException e)	{
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
