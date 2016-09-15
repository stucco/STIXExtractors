package gov.ornl.stucco.stix_extractors;

import gov.ornl.stucco.utils.STIXUtils;

import gov.ornl.stucco.utils.STIXUtils;

import java.util.List;
import java.util.ArrayList;

import java.io.IOException;

import org.apache.commons.csv.CSVRecord;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.xml.datatype.DatatypeConfigurationException;

import org.mitre.stix.stix_1.STIXPackage;
import org.mitre.cybox.cybox_2.Observable;
import org.mitre.cybox.cybox_2.Observables;
import org.mitre.stix.ttp_1.BehaviorType;
import org.mitre.stix.ttp_1.MalwareType;
import org.mitre.stix.ttp_1.InfrastructureType;
import org.mitre.stix.ttp_1.ResourceType;
import org.mitre.stix.stix_1.TTPsType;

/**
 * CIF Emerging Threats data to STIX format extractor
 *
 * @author Maria Vincent
 */
public class CIFEmergingThreatsExtractor extends STIXUtils {
						
	private static final Logger logger = LoggerFactory.getLogger(CIFEmergingThreatsExtractor.class);
	private static final String[] HEADERS = {"ip"};
	private static final String IP = "ip";
	private STIXPackage stixPackage;

	public CIFEmergingThreatsExtractor(String cifInfo) {
		stixPackage = extract(cifInfo);
	}
					
	public STIXPackage getStixPackage() {
		return stixPackage;
	}

	private STIXPackage extract (String cifInfo) {
		List<CSVRecord> records;
		try {
			records = getCSVRecordsList(HEADERS, cifInfo);
		} catch (IOException e) {
			e.printStackTrace();
			return null;
		} 
		if (records.size() == 0) {
			return null;
		}

		CSVRecord record = records.get(0);
		int start;
		if (record.get(0).equals(IP)) {
			if (records.size() == 1) {
				return null;
			}
			else {
				start = 1;
			}
		}
		else {
			start = 0;
		}
		
		Observables observables = initObservables();
		List<Observable> ipIdList = new ArrayList<Observable>();

	 	for (int i = start; i < records.size(); i++) {
	 		try {
				record = records.get(i);

				if (!record.get(IP).isEmpty()) {
				//	observable = setIpObservable(record.get(IP), ipToLong(record.get(IP)), "Malware", "rules.emergingthreats.net");
					Observable observable = setIpObservable(record.get(IP), ipToLong(record.get(IP)), "rules.emergingthreats.net");
					observables
						.withObservables(observable);
					ipIdList.add(new Observable()
						.withIdref(observable.getId()));
				}
			} catch (RuntimeException e) {
				e.printStackTrace();
			}
		}
		if (!ipIdList.isEmpty()) {
			try {
				stixPackage = initStixPackage("Malicious IP Addresses", "rules.emergingthreats.net", "rules.emergingthreats.net")
					.withObservables(observables)
					.withTTPs(new TTPsType()
						.withTTPS(initTTP("Malware", "rules.emergingthreats.net")
	        		.withBehavior(new BehaviorType()
	           		.withMalware(new MalwareType()
	             		.withMalwareInstances(setMalwareInstance("Malware", "rules.emergingthreats.net"))))
							.withResources(new ResourceType()
								.withInfrastructure(new InfrastructureType()
									.withObservableCharacterization(initObservables()
										.withObservables(ipIdList))))));
			} catch (DatatypeConfigurationException e) {
				e.printStackTrace();
			}
		}

		return stixPackage;
	}
}
