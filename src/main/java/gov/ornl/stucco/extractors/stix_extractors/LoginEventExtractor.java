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
import javax.xml.namespace.QName;					

import org.mitre.stix.stix_1.STIXPackage;
import org.mitre.cybox.cybox_2.Observables;
import org.mitre.cybox.cybox_2.Observable;
import org.mitre.cybox.cybox_2.RelatedObjectType;
import org.mitre.cybox.cybox_2.RelatedObjectsType;
import org.mitre.cybox.common_2.DateTimeObjectPropertyType;
import org.mitre.cybox.common_2.ControlledVocabularyStringType;
import org.mitre.cybox.objects.UserSession;

/**
 * LoginEvent to STIX format extractor.
 *
 * @author Maria Vincent
 */
public class LoginEventExtractor extends STIXUtils {
						
	private static final Logger logger = LoggerFactory.getLogger(LoginEventExtractor.class);

	private static final String[] HEADERS = {"date_time","hostname","login_software","status","user","from_ip"};
	private static final String DATE_TIME = "date_time";
	private static final String HOSTNAME = "hostname";
	private static final String LOGIN_SOFTWARE = "login_software";
	private static final String STATUS = "status";
	private static final String USER = "user";
	private static final String FROM_IP = "from_ip";
	
	private STIXPackage stixPackage;

	public LoginEventExtractor(String loginEventInfo) {
		stixPackage = extract(loginEventInfo);
	}
					
	public STIXPackage getStixPackage() {
		return stixPackage;
	}

	private STIXPackage extract (String loginEventInfo) {
		List<CSVRecord> records;
		try {
			records = getCSVRecordsList(HEADERS, loginEventInfo);
		} catch (IOException e) {
			e.printStackTrace();
			return null;
		}			
		if (records.isEmpty()) {
			return null;
		}

		CSVRecord record = records.get(0);
		int start;
		if (record.get(0).equals(DATE_TIME)) {
			if (records.size() == 1) {
				return null;
			} else {
				start = 1;
			}
		}
		else start = 0;
					
		Observables observables = initObservables();

	 	for (int i = start; i < records.size(); i++) {
	 		try {
				record = records.get(i);

				Observable hostnameObservable = null;
				Observable accountObservable = null;
				Observable softwareObservable = null;
				Observable hostAtIpObservable = null;
				Observable ipObservable = null;
				
				/* hostname */
				if (!record.get(HOSTNAME).isEmpty()) {
					hostnameObservable = setHostObservable(record.get(HOSTNAME), "LoginEvent");
				}

				/* account */
				if (!record.get(USER).isEmpty()) {
					accountObservable = setAccountObservable(record.get(USER), "LoginEvent");
				}
				
				/* software */
				if (!record.get(LOGIN_SOFTWARE).isEmpty()) {
					softwareObservable = setSoftwareObservable(record.get(LOGIN_SOFTWARE), "LoginEvent");
					observables
						.withObservables(softwareObservable);
				}

				/* IP */
				if (!record.get(FROM_IP).isEmpty()) {
					ipObservable = setIpObservable(record.get(FROM_IP), "LoginEvent");
					observables
						.withObservables(ipObservable);
				}

				/* host */
				if (!record.get(FROM_IP).isEmpty()) {
					hostAtIpObservable = setHostObservable("host_at_" + record.get(FROM_IP), "LoginEvent");	
				}

				if (accountObservable != null) {
					List<RelatedObjectType> relatedObjects = new ArrayList<RelatedObjectType>();

					/* account -> hostname relation */
					if (hostnameObservable != null) {
						relatedObjects.add(
							setRelatedObject(hostnameObservable.getId())  
								.withState(new ControlledVocabularyStringType()
									.withValue(record.get(STATUS)))
								.withProperties(new UserSession()
									.withLoginTime(new DateTimeObjectPropertyType()
										.withValue(record.get(DATE_TIME)))));
					}
					
					/* account -> ip relation */
					if (ipObservable != null) {
						relatedObjects.add(
							setRelatedObject(hostAtIpObservable.getId()) 
								.withState(new ControlledVocabularyStringType()
									.withValue(record.get(STATUS)))
								.withProperties(new UserSession()
									.withLoginTime(new DateTimeObjectPropertyType()
										.withValue(record.get(DATE_TIME)))));
					}
					
					accountObservable
						.getObject()
							.withRelatedObjects(new RelatedObjectsType()
								.withRelatedObjects(relatedObjects));
					observables
						.withObservables(accountObservable);
				}

				/* host -> software relation */
				if (hostnameObservable != null) {
					if (softwareObservable != null) {
						hostnameObservable
							.getObject()
								.withRelatedObjects(new RelatedObjectsType()
									.withRelatedObjects(setRelatedObject(softwareObservable.getId())));
					}
					observables
						.withObservables(hostnameObservable);
				}

				/* hostAtIp -> ip */
				if (hostAtIpObservable != null) {
					if (ipObservable != null) {
						hostAtIpObservable
							.getObject()
								.withRelatedObjects(new RelatedObjectsType()
									.withRelatedObjects(
										setRelatedObject(ipObservable.getId())));
					}
					observables
						.withObservables(hostAtIpObservable);
				}
			} catch (RuntimeException e) {
				e.printStackTrace();
			}
		}
		if (!observables.getObservables().isEmpty()) {
			try {
				stixPackage = initStixPackage("Login Event", "LoginEvent")
					.withObservables(observables);
			} catch (DatatypeConfigurationException e) {
				e.printStackTrace();
			} 
		}

		return stixPackage;
	}
}
