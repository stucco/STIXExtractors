package STIXExtractor;

import java.util.List;
import java.util.ArrayList;

import java.io.IOException;

import javax.xml.datatype.DatatypeConfigurationException;

import org.apache.commons.csv.CSVRecord;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.mitre.stix.stix_1.STIXPackage;
import org.mitre.stix.stix_1.IndicatorsType;
import org.mitre.cybox.cybox_2.Observable;
import org.mitre.cybox.cybox_2.Observables;
import org.mitre.cybox.cybox_2.ObservableCompositionType;
import org.mitre.cybox.cybox_2.OperatorTypeEnum;

/**
 * CIF Zeus Tracker data to STIX format extractor
 *
 * @author Maria Vincent
 */
public class CIFZeusTrackerExtractor extends STIXExtractor {
						
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

			Observable observable = new Observable();
			Observables observables = initObservables();
			List<Observable> ipIdList = new ArrayList<Observable>();

		 	for (int i = start; i < records.size(); i++)	{
			
				record = records.get(i);

				//avoid empty lines and comments
				if (!record.get(IP).isEmpty() && !record.get(IP).startsWith("#")) {
					observable = setIpObservable(record.get(IP), ipToLong(record.get(IP)), "Botnet", "zeustracker.abuse.ch");
					observables
						.withObservables(observable);
					ipIdList.add(new Observable()
						.withIdref(observable.getId()));
				}
			}
										
			return (ipIdList.isEmpty()) ? null : initStixPackage("zeustracker.abuse.ch")
					.withIndicators(new IndicatorsType()
						.withIndicators(setMalwareIndicator("Botnet", "zeustracker.abuse.ch")
							.withObservable((ipIdList.size() == 1) ? ipIdList.get(0) : new Observable()
								.withObservableComposition(new ObservableCompositionType()
									.withOperator(OperatorTypeEnum.AND)
									.withObservables(ipIdList)))))
					.withObservables(observables);

		} catch (DatatypeConfigurationException e) {
			e.printStackTrace();
		} catch (IOException e)	{
			e.printStackTrace();
		}

		return null;
	}
}
