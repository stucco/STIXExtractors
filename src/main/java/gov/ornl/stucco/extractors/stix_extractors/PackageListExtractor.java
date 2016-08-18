package gov.ornl.stucco.stix_extractors;

import gov.ornl.stucco.utils.STIXUtils;

import java.util.List;
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
import org.mitre.cybox.cybox_2.ObjectType;
import org.mitre.cybox.cybox_2.RelatedObjectType;
import org.mitre.cybox.cybox_2.RelatedObjectsType;
import org.mitre.cybox.common_2.Property;
import org.mitre.cybox.common_2.StringObjectPropertyType;
import org.mitre.cybox.common_2.StructuredTextType;
import org.mitre.cybox.objects.Product;

/**
 * PackageList to STIX extractor
 *
 * @author Maria Vincent
 */
public class PackageListExtractor extends STIXUtils {
						
	private static final Logger logger = LoggerFactory.getLogger(PackageListExtractor.class);
	private static final String[] HEADERS = {"hostname", "package", "version"};
	private static final String HOSTNAME = "hostname";
	private static final String PACKAGE = "package";
	private static final String VERSION = "version";
	
	private STIXPackage stixPackage;

	public PackageListExtractor(String packageInfo) {
		stixPackage = extract(packageInfo);
	}
					
	public STIXPackage getStixPackage() {
		return stixPackage;
	}

	private STIXPackage extract (String packageInfo) {
		List<CSVRecord> records;
		try {
			records = getCSVRecordsList(HEADERS, packageInfo);
		} catch (IOException e) {
			e.printStackTrace();
			return null;
		}
		if (records.isEmpty()) {
 			return null;
		}

		CSVRecord record = records.get(0);
		int start;
		if (record.get(0).equals(HOSTNAME)) {
			if (records.size() == 1) {
				return null;
			} else {
				start = 1;
			}
		} else {
			start = 0;
		}
		
		Observables observables = initObservables();

	 	for (int i = start; i < records.size(); i++) {
			record = records.get(i);

			Observable hostObservable = null;		
			Observable softwareObservable = null;		

			/* host */
			if (!record.get(HOSTNAME).isEmpty()) {
				hostObservable = setHostObservable(record.get(HOSTNAME), "PackageList");
			}

			/* software */
			if (!record.get(PACKAGE).isEmpty() && !record.get(VERSION).isEmpty()) {
				softwareObservable = new Observable()		
					.withId(new QName("gov.ornl.stucco", "software-" + UUID.randomUUID().toString(), "stucco"))
					.withTitle("Software")
					.withObservableSources(setMeasureSourceType("PackageList"))
					.withObject(new ObjectType()
						.withId(new QName("gov.ornl.stucco", "software-" + record.get(PACKAGE) + "_" + record.get(VERSION), "stucco"))
						.withDescription(new StructuredTextType()
							.withValue(record.get(PACKAGE) + " version " + record.get(VERSION)))
						.withProperties(new Product()
							.withProduct(new StringObjectPropertyType()
								.withValue(record.get(PACKAGE)))
							.withVersion(new StringObjectPropertyType()
								.withValue(record.get(VERSION)))));
				observables
					.withObservables(softwareObservable);
			}
			
			/* host -> software */
			if (hostObservable != null && softwareObservable != null) {
				hostObservable
					.getObject()
						.withRelatedObjects(new RelatedObjectsType()
							.withRelatedObjects(setRelatedObject(softwareObservable.getId(), "Runs", 
								record.get(HOSTNAME) + " runs " + record.get(PACKAGE) + "_" + record.get(VERSION), "PackageList")));
			}

			if (hostObservable != null) {
				observables
					.withObservables(hostObservable);
			}
		}

		if (!observables.getObservables().isEmpty()) {
			try {
				stixPackage = initStixPackage("Software Description", "PackageList")	
					.withObservables(observables);
			} catch (DatatypeConfigurationException e) {
				e.printStackTrace();
			}
		}
			
		return stixPackage;
	}
}
