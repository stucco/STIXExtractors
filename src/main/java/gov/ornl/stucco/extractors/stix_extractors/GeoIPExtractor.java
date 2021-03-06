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

public class GeoIPExtractor extends STIXUtils {
						
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
		List<CSVRecord> records;
		try {
			records = getCSVRecordsList (HEADERS, geoIpInfo);
		} catch (IOException e) {
			e.printStackTrace();
			return null;
		}	
		if (records.isEmpty()) {
			return null;
		}
		
		CSVRecord record = records.get(0);
		int start;
		if (record.get(0).equals(STARTIP)) {
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
	 		try {
				record = records.get(i);

				/* ip */
				observables																
					.withObservables(new Observable()
						.withId(new QName("gov.ornl.stucco", "addressRange-" + UUID.randomUUID().toString(), "stucco"))
						.withTitle("AddressRange")
						.withObservableSources(setMeasureSourceType("Maxmind"))
						.withObject(new ObjectType()
							.withId(new QName("gov.ornl.stucco", "addressRange-" + record.get(STARTIPINT) + "-" + record.get(ENDIPINT), "stucco"))
							.withDescription(new org.mitre.cybox.common_2.StructuredTextType()
								.withValue(record.get(STARTIP) + " through " + record.get(ENDIP)))
							.withLocation(new LocationType()
								.withId(new QName("gov.ornl.stucco", "countryCode-" + record.get(COUNTRYCODE), "stucco"))
								.withName(record.get(COUNTRYNAME)))
							.withProperties(new Address()
								.withAddressValue(new StringObjectPropertyType()
									.withValue(record.get(STARTIP) + " - " + record.get(ENDIP))
								.withCondition(ConditionTypeEnum.INCLUSIVE_BETWEEN)
								.withApplyCondition(ConditionApplicationEnum.ANY)
								.withDelimiter(" - "))
								.withCategory(CategoryTypeEnum.IPV_4_ADDR))));
			} catch (RuntimeException e) {
				e.printStackTrace();
			}
		}

		if (!observables.getObservables().isEmpty()) {
			try {
				stixPackage = initStixPackage("IP List", "Maxmind")
					.withObservables(observables);
			} catch (DatatypeConfigurationException e) {
				e.printStackTrace();
			}
		}

		return stixPackage;
	}
}
