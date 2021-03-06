package gov.ornl.stucco.stix_extractors;

import gov.ornl.stucco.utils.STIXUtils;

import java.util.List;
import java.util.UUID;

import java.io.IOException;

import javax.xml.namespace.QName;
import javax.xml.datatype.DatatypeConfigurationException;

import org.apache.commons.csv.CSVRecord;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.mitre.stix.stix_1.STIXPackage;
import org.mitre.cybox.cybox_2.Observables;
import org.mitre.cybox.cybox_2.Observable;
import org.mitre.cybox.common_2.CustomPropertiesType; 

/**
 * Banner to STIX format extractor.
 *
 * @author Maria Vincent
 */
public class BannerExtractor extends STIXUtils {
						
	private static final Logger logger = LoggerFactory.getLogger(BannerExtractor.class);
	private static String[] HEADERS = {"filename","recnum","file_type","amp_version","site","banner","addr","app_protocol","times_seen",
					   "first_seen","last_seen","cc","org","lat","lon"};
	private static final String FILENAME = "filename";
	private static final String ADDR = "addr";
	private static final String APP_PROTOCOL = "app_protocol";
	private static final String BANNER = "banner";


	private STIXPackage stixPackage;
	private Observables observables;
	
	public BannerExtractor(String bannerInfo) {
		stixPackage = extract(bannerInfo);
	}
					
	public STIXPackage getStixPackage() {
		return stixPackage;
	}

	private STIXPackage extract (String bannerInfo) {
		List<CSVRecord> records;
		try {
			records = getCSVRecordsList(HEADERS, bannerInfo);
		} catch (IOException e) {
			e.printStackTrace();
			return null;
		}
		if (records.isEmpty()) {
			return null;
		}

		CSVRecord record = records.get(0);
		int start;
		if (record.get(0).equals(FILENAME))	{
			if (records.size() == 1)	{
				return null;
			} else {
				start = 1;
			}
		} else {
			start = 0;
		}
					
		observables = initObservables();

		for (int i = start; i < records.size(); i++) {
			try {
				record = records.get(i);
				
				Observable ipObservable = null;
				Observable portObservable = null;
				Observable addressObservable = null;

				/* IP */
				if (!record.get(ADDR).isEmpty()) {
					ipObservable = setIpObservable(record.get(ADDR), "banner");
					observables
						.withObservables(ipObservable);
				}

				/* Port */
				if (!record.get(APP_PROTOCOL).isEmpty()) {
					portObservable = setPortObservable(record.get(APP_PROTOCOL), "banner");
					observables
						.withObservables(portObservable);
				}

				/* Address */
				if (ipObservable != null && portObservable != null) {
					addressObservable = setAddressObservable(record.get(ADDR), ipToLong(record.get(ADDR)), ipObservable.getId(), 
						record.get(APP_PROTOCOL), portObservable.getId(), "banner");
					if (!record.get(BANNER).isEmpty()) {
						addressObservable
							.getObject()			
								.getProperties()
									.withCustomProperties(new CustomPropertiesType()
										.withProperties(setCustomProperty("Banner", record.get(BANNER))));
					}

					observables
						.withObservables(addressObservable);
				}
			} catch (RuntimeException e) {
				e.printStackTrace();
			}
		}

		if (!observables.getObservables().isEmpty()) {
			try {
				stixPackage = initStixPackage("Banner", "banner")
					.withObservables(observables);	
			} catch (DatatypeConfigurationException e) {
				e.printStackTrace();
			}
		}

		return stixPackage;
	}
}
