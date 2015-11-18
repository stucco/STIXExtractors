package STIXExtractor;

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
 * client_banner to STIX format extractor.
 *
 * @author Maria Vincent
 */
public class ClientBannerExtractor extends STIXExtractor {
						
	private static final Logger logger = LoggerFactory.getLogger(ClientBannerExtractor.class);
	private static String[] HEADERS = {"filename","recnum","file_type","amp_version","site","banner","addr","app_protocol","times_seen",
					   "first_seen_timet","last_seen_timet","countrycode","organization","lat","long"};
	private static final String FILENAME = "filename";
	private static final String ADDR = "addr";
	private static final String APP_PROTOCOL = "app_protocol";
	private static final String BANNER = "banner";


	private STIXPackage stixPackage;
	private Observables observables;
	
	public ClientBannerExtractor(String clientBannerInfo) {
		stixPackage = extract(clientBannerInfo);
	}
					
	public STIXPackage getStixPackage() {
		return stixPackage;
	}

	private STIXPackage extract (String clientBannerInfo) {
		try {
			List<CSVRecord> records = getCSVRecordsList(HEADERS, clientBannerInfo);
			
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
						
			stixPackage = initStixPackage("Client Banner", "client_banner");				
			observables = initObservables();

			for (int i = start; i < records.size(); i++) {

				record = records.get(i);
				
				Observable ipObservable = null;
				Observable portObservable = null;
				Observable addressObservable = null;

				/* IP */
				if (!record.get(ADDR).isEmpty()) {
					ipObservable = setIpObservable(record.get(ADDR), "client_banner");
					observables
						.withObservables(ipObservable);
				}

				/* Port */
				if (!record.get(APP_PROTOCOL).isEmpty()) {
					portObservable = setPortObservable(record.get(APP_PROTOCOL), "client_banner");
					observables
						.withObservables(portObservable);
				}

				/* Address */
				if (ipObservable != null && portObservable != null) {
					addressObservable = setAddressObservable(record.get(ADDR), ipToLong(record.get(ADDR)), ipObservable.getId(), 
						record.get(APP_PROTOCOL), portObservable.getId(), "client_banner");
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

			return (observables.getObservables().isEmpty()) ? null : initStixPackage("client_banner").withObservables(observables);	

		} catch (DatatypeConfigurationException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}

		return null;
	}
}
