package STIXExtractor;

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
 * CIF 1d4 data to STIX format extractor
 *
 * @author Maria Vincent
 */
public class CIF1d4Extractor extends STIXExtractor {
						
	private static final Logger logger = LoggerFactory.getLogger(CIF1d4Extractor.class);
	private static final String[] HEADERS = { "ip" };
	private static final String IP = "ip";
	private STIXPackage stixPackage;

	public CIF1d4Extractor(String cifInfo) {
		stixPackage = extract(cifInfo);
	}

	public STIXPackage getStixPackage() {
		return stixPackage;
	}

	private STIXPackage extract (String cifInfo) {
		try {
			List<CSVRecord> records = getCSVRecordsList(HEADERS, cifInfo);
			
			if (records.isEmpty()) {
				return null;
			}
			
			//calculating start to avoid header line
			CSVRecord record = records.get(0);
			int start;
			if (record.get(0).equals(IP)) {
				if (records.size() == 1)	{
					return null;
				} else {
					start = 1;
				}
			} else {
				start = 0;
			}
			
			//has to modify source name from 1d4.us to oneDFour.us to pass validation
			Observable observable = new Observable();
			Observables observables = initObservables();
			List<Observable> ipIdList = new ArrayList<Observable>();

		 	for (int i = start; i < records.size(); i++) {
				
				record = records.get(i);

				if (!record.get(IP).isEmpty()) {
					observable = setIpObservable(record.get(IP), ipToLong(record.get(IP)), "Scanner", "1d4.us");
					observables
						.withObservables(observable);
					ipIdList.add(new Observable()
						.withIdref(observable.getId()));
				}
			}
		
			return (ipIdList.isEmpty()) ? null : initStixPackage("OneDFour_US")
					.withObservables(observables)
					.withTTPs(new TTPsType()
						.withTTPS(initTTP("Malware", "1d4.us")
                                   			.withBehavior(new BehaviorType()
                                           			.withMalware(new MalwareType()
                                                      			.withMalwareInstances(setMalwareInstance("Scanner", "1d4.us"))))
							.withResources(new ResourceType()
								.withInfrastructure(new InfrastructureType()
									.withObservableCharacterization(initObservables()
										.withObservables(ipIdList))))));
											
		} catch (DatatypeConfigurationException e) {
			e.printStackTrace();
		} catch (IOException e)	{
			e.printStackTrace();
		}

		return null;
	}
}
