package STIXExtractor;

import java.util.UUID;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.namespace.QName;					

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

/**
 * CPE to STIX format extractor.
 *
 * @author Maria Vincent
 */
public class CpeExtractor extends STIXExtractor {
						
	private static final Logger logger = LoggerFactory.getLogger(CpeExtractor.class);
	
	private STIXPackage stixPackage;

	public CpeExtractor(String cpeInfo) {
		stixPackage = extract(cpeInfo);
	}
					
	public STIXPackage getStixPackage() {
		return stixPackage;
	}

	private STIXPackage extract(String cpeInfo) {
		try {
			Document doc = Jsoup.parse(cpeInfo);
			Elements entries = doc.select("cpe-item");

			if (entries.isEmpty()) {
				return null;
			}
			
			Observables observables = initObservables();

			for (Element entry : entries) {	
		
				Product product = new Product();
				String[] cpe = entry.attr("name").split(":");

				if (cpe.length == 0) {
					continue;
				}
		
				for (int i = 1; i < cpe.length; i++) {
					if (cpe[i].isEmpty()) {
						continue;
					}

					switch (i) {
					case 1:	
						product
							.withCustomProperties(new CustomPropertiesType()
								.withProperties(setCustomProperty("Part", cpe[1])));
						break;
					case 2:	
						product
							.withVendor(new StringObjectPropertyType()
								.withValue(cpe[2]));
						break;
					case 3:	
						product
							.withProduct(new StringObjectPropertyType()
								.withValue(cpe[3]));
						break;
					case 4:	
						product
							.withVersion(new StringObjectPropertyType()
								.withValue(cpe[4]));
						break;
					case 5:	
						product 
							.withUpdate(new StringObjectPropertyType()
								.withValue(cpe[5]));
						break;
					case 6:	
						product
							.withEdition(new StringObjectPropertyType()
								.withValue(cpe[6]));
						break;
					case 7:	
						product
							.withLanguage(new StringObjectPropertyType()
								.withValue(cpe[7]));
						break;
					}
				}		

				/* software */
				observables
					.withObservables(new Observable()
                       				.withId(new QName("gov.ornl.stucco", "software-" + UUID.randomUUID().toString(), "stucco"))
                        			.withTitle("Software")
						.withObservableSources(setMeasureSourceType("CPE"))
                                 		.withObject(new ObjectType()
                                         		.withId(new QName("gov.ornl.stucco", "software-" + makeId(entry.attr("name")), "stucco"))
                                   			.withDescription(new StructuredTextType()
                                   				.withValue((!entry.select("title[xml:lang=en-US]").text().isEmpty())
                                                			? entry.select("title[xml:lang=en-US]").text() : makeSoftwareDesc(entry.attr("name"))))
							.withProperties(product)));
	 		}

			return (observables.getObservables().isEmpty()) ? null : initStixPackage("Software Description", "CPE").withObservables(observables);

		} catch (DatatypeConfigurationException e) {
			e.printStackTrace();
		} 
		return null;
	}
}
