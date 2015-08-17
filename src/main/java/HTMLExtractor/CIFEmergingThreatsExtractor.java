package STIXExtractor;

import java.util.List;

import java.io.IOException;

import org.apache.commons.csv.CSVRecord;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.xml.datatype.DatatypeConfigurationException;

import org.mitre.stix.stix_1.STIXPackage;
import org.mitre.cybox.cybox_2.Observables;

/**
 * CIF Emerging Threats data to STIX format extractor
 *
 * @author Maria Vincent
 */
public class CIFEmergingThreatsExtractor extends HTMLExtractor	{
						
	private static final Logger logger = LoggerFactory.getLogger(CIFEmergingThreatsExtractor.class);
	private static final String[] HEADERS = {"ip"};
	private static final String IP = "ip";
	private STIXPackage stixPackage;

	public CIFEmergingThreatsExtractor(String cifInfo)	{
		stixPackage = extract(cifInfo);
	}
					
	public STIXPackage getStixPackage() {
		return stixPackage;
	}

	private STIXPackage extract (String cifInfo)	{
		try {
			List<CSVRecord> records = getCSVRecordsList(HEADERS, cifInfo);
			
			if (records.size() == 0) {
				return null;
			}
			CSVRecord record = records.get(0);

			//calculating the starting point to avoid header and/or empty document
			int start;

			if (record.get(0).equals(IP))	{
				if (record.size() == 1) {
					return null;
				}
				else {
					start = 1;
				}
			}
			else {
				start = 0;
			}
			
			stixPackage = initStixPackage("rules.emergingthreats.net");
			Observables observables = initObservables();

		 	for (int i = start; i < records.size(); i++)	{
				record = records.get(i);
				observables
					.withObservables(setIpObservable(record.get(IP), ipToLong(record.get(IP)), "Malware", "rules.emergingthreats.net"));	
			}
				
			return stixPackage 
					.withObservables(observables);

		} catch (DatatypeConfigurationException e) {
			e.printStackTrace();
		} catch (IOException e)	{
			e.printStackTrace();
		}

		return null;
	}
}
