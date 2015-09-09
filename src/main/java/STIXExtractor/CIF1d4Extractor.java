package STIXExtractor;

import java.util.List;
import java.util.ArrayList;

import java.io.IOException;

import org.apache.commons.csv.CSVRecord;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.xml.datatype.DatatypeConfigurationException;

import org.mitre.stix.stix_1.STIXPackage;
import org.mitre.stix.stix_1.IndicatorsType;
import org.mitre.cybox.cybox_2.Observable;
import org.mitre.cybox.cybox_2.Observables;
import org.mitre.cybox.cybox_2.ObservableCompositionType;
import org.mitre.cybox.cybox_2.OperatorTypeEnum;

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
				if (record.size() == 1)	{
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
					.withIndicators(new IndicatorsType()
						.withIndicators(setMalwareIndicator("Scanner", "1d4.us")
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
