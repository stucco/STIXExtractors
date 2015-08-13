package STIXExtractor;

import java.util.List;

import java.io.IOException;

import javax.xml.datatype.DatatypeConfigurationException;

import org.apache.commons.csv.CSVRecord;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.mitre.stix.stix_1.STIXPackage;
import org.mitre.cybox.cybox_2.Observables;

/**
 * CIF Zeus Tracker data to STIX format extractor
 *
 * @author Maria Vincent
 */
public class CIFZeusTrackerExtractor extends HTMLExtractor {
						
	private static final Logger logger = LoggerFactory.getLogger(CIFZeusTrackerExtractor.class);
	private static final String[] HEADERS = {"ip"};
	private static final String IP = "ip";	
	private STIXPackage stixPackage;

	public CIFZeusTrackerExtractor(String cifInfo) {
		stixPackage = extract(cifInfo);
	}

	public STIXPackage getStixPackage() {
		return stixPackage;
	}

	private STIXPackage extract(String cifInfo) {
		try {
			List<CSVRecord> records = getCSVRecordsList(HEADERS, cifInfo);

			if (records.size() == 0) {
				return null;
			}
			CSVRecord record = records.get(0);

			//calculating starting point to avoid header or/and empty document
			int start;	
			if (record.get(0).equals(IP))	{
				if (record.size() == 1) {
					return null;
				} else {
					start = 1;
				}
			} else {
				start = 0;
			}
			stixPackage = initStixPackage("zeustracker.abuse.ch");				
			Observables observables = initObservables();

		 	for (int i = start; i < records.size(); i++)	{
				record = records.get(i);

				//avoid empty lines and comments
				if (!record.get(IP).isEmpty() && !record.get(IP).startsWith("#")) {
					observables
						.withObservables(setIpObservable(record.get(IP), "Botnet", "zeustracker.abuse.ch"));
				}
			}

			return (!observables.getObservables().isEmpty()) ? stixPackage.withObservables(observables) : null;

		} catch (DatatypeConfigurationException e) {
			e.printStackTrace();
		} catch (IOException e)	{
			e.printStackTrace();
		}

		return null;
	}
}
