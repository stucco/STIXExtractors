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
 * server_banner to STIX format extractor.
 *
 * @author Maria Vincent
 */
public class ServerBannerExtractor extends STIXUtils {
						
	private static final Logger logger = LoggerFactory.getLogger(ServerBannerExtractor.class);
	private static String[] HEADERS = {"filename","recnum","file_type","amp_version","site","banner","addr","app_protocol","times_seen",
					   "first_seen_timet","last_seen_timet","countrycode","organization","lat","long"};
	private static final String FILENAME = "filename";
	private static final String ADDR = "addr";
	private static final String APP_PROTOCOL = "app_protocol";
	private static final String BANNER = "banner";


	private STIXPackage stixPackage;
	private Observables observables;
	
	public ServerBannerExtractor(String serverBannerInfo) {
		stixPackage = extract(serverBannerInfo);
	}
					
	public STIXPackage getStixPackage() {
		return stixPackage;
	}

	private STIXPackage extract (String serverBannerInfo) {
		List<CSVRecord> records;
		try {
			records = getCSVRecordsList(HEADERS, serverBannerInfo);
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
			record = records.get(i);
			
			Observable ipObservable = null;
			Observable portObservable = null;
			Observable addressObservable = null;

			/* IP */
			if (!record.get(ADDR).isEmpty()) {
				ipObservable = setIpObservable(record.get(ADDR), "server_banner");
				observables
					.withObservables(ipObservable);
			}

			/* Port */
			if (!record.get(APP_PROTOCOL).isEmpty()) {
				portObservable = setPortObservable(record.get(APP_PROTOCOL), "server_banner");
				observables
					.withObservables(portObservable);
			}

			/* Address */
			if (ipObservable != null && portObservable != null) {
				addressObservable = setAddressObservable(record.get(ADDR), ipToLong(record.get(ADDR)), ipObservable.getId(), 
					record.get(APP_PROTOCOL), portObservable.getId(), "server_banner");
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
		}

		if (!observables.getObservables().isEmpty()) {
			try {
				stixPackage = initStixPackage("Server Banner", "server_banner")
					.withObservables(observables);	
			} catch (DatatypeConfigurationException e) {
				e.printStackTrace();
			}
		}

		return stixPackage;
	}
}
