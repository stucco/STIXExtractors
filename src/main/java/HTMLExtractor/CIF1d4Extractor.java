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
 * CIF 1d4 data to STIX format extractor
 *
 * @author Maria Vincent
 */
public class CIF1d4Extractor extends HTMLExtractor {
						
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
		try	{
			List<CSVRecord> records = getCSVRecordsList(HEADERS, cifInfo);
			
			if (records.size() == 0) {
				return null;
			}
			
			//calculating start to avoid header line
			CSVRecord record = records.get(0);
			int start;

			if (record.get(0).equals(IP))	{
				if (record.size() == 1)	{
					return null;
				} else {
					start = 1;
				}
			} else {
				start = 0;
			}
			
			//has to modify source name from 1d4.us to oneDFour.us to pass validation
			stixPackage = initStixPackage("oneDFour.us");				
			Observables observables = initObservables();

		 	for (int i = start; i < records.size(); i++)	{
				record = records.get(i);
				observables
					.withObservables(setIpObservable(record.get(IP), ipToLong(record.get(IP)), "Scanner", "1d4.us"));
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
