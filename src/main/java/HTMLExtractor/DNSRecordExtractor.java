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
import org.mitre.cybox.common_2.Property;
import org.mitre.cybox.common_2.ControlledVocabularyStringType;
import org.mitre.cybox.common_2.CustomPropertiesType;
import org.mitre.cybox.common_2.StringObjectPropertyType;
import org.mitre.cybox.common_2.DateTimeObjectPropertyType;
import org.mitre.cybox.common_2.StructuredTextType;
import org.mitre.cybox.common_2.HexBinaryObjectPropertyType;
import org.mitre.cybox.common_2.IntegerObjectPropertyType;
import org.mitre.cybox.cybox_2.Observables;
import org.mitre.cybox.cybox_2.Observable;
import org.mitre.cybox.cybox_2.ObjectType;
import org.mitre.cybox.cybox_2.RelatedObjectsType;
import org.mitre.cybox.cybox_2.AssociatedObjectType;
import org.mitre.cybox.cybox_2.AssociatedObjectsType;
import org.mitre.cybox.cybox_2.ActionType;
import org.mitre.cybox.cybox_2.ActionsType;
import org.mitre.cybox.cybox_2.Event;
import org.mitre.cybox.cybox_2.RelatedObjectType;
import org.mitre.cybox.objects.DNSRecordType;
import org.mitre.cybox.objects.DNSQuestionType;
import org.mitre.cybox.objects.DNSQuery;
import org.mitre.cybox.objects.WhoisContactType;
import org.mitre.cybox.objects.WhoisEntry;
import org.mitre.cybox.objects.DNSRecord;
import org.mitre.cybox.objects.DNSResourceRecordsType;
import org.mitre.cybox.objects.DNSRecord;
import org.mitre.cybox.objects.Address;
import org.mitre.cybox.objects.WhoisNameserversType;

/**
 * DNS record to STIX format extractor.
 *
 * @author Maria Vincent
 */
public class DNSRecordExtractor extends HTMLExtractor {
						
	private static final Logger logger = LoggerFactory.getLogger(DNSRecordExtractor.class);
	private static String[] HEADERS = {"filename", "recnum", "file_type", "amp_version", "site", "saddr", "daddr", "ttl", "rqtype", "flags", "rqfqdn",
					   "refqdn", "raddr", "preference", "answer_ns", "authoritative_ns", "times_seen", "first_seen_timet", "last_seen_timet", 
					   "scountrycode", "sorganization", "dcountrycode", "dorganization", "rcountrycode", "rorganization"};
	private static final String FILENAME = "filename";	
	private static final String RECNUM = "recnum";	
	private static final String FILE_TYPE = "file_type";	
	private static final String AMP_VERSION = "amp_version";	
	private static final String SITE = "site";	
	private static final String SADDR = "saddr";	
	private static final String DADDR = "daddr";	
	private static final String TTL = "ttl";	
	private static final String RQTYPE = "rqtype";	
	private static final String FLAGS = "flags";	
	private static final String RQFQDN = "rqfqdn";	
	private static final String REFQDN = "refqdn";	
	private static final String RADDR = "raddr";	
	private static final String PREFERENCE = "preference";	
	private static final String ANSWER_NS = "answer_ns";	
	private static final String AUTHORITATIVE_NS = "authoritative_ns";	
	private static final String TIMES_SEEN = "times_seen";	
	private static final String FIRST_SEEN_TIMET = "first_seen_timet";	
	private static final String LAST_SEEN_TIMET = "last_seen_timet";	
	private static final String SCOUNTRYCODE = "scountrycode";	
	private static final String SORGANIZATION = "sorganization";	
	private static final String DCOUNTRYCODE = "dcountrycode";	
	private static final String DORGANIZATION = "dorganization";	
	private static final String RCOUNTRYCODE = "rcountrycode";	
	private static final String RORGANIZATION = "rorganization";	

	private STIXPackage stixPackage;
	private Observables observables;
	
	public DNSRecordExtractor(String dnsInfo) {
		stixPackage = extract(dnsInfo);
	}
					
	public STIXPackage getStixPackage() {
		return stixPackage;
	}

	private STIXPackage extract (String dnsInfo) {

		try {
			stixPackage = initStixPackage("DNSRecord");				
			observables = initObservables();
			List<CSVRecord> records = getCSVRecordsList(HEADERS, dnsInfo);
			CSVRecord record = records.get(0);
			int start;

			/* computing a start of iteration */
			if (record.get(0).equals(FILENAME))	{
				if (record.size() == 1)	{
					return null;
				} else {
					start = 1;
				}
			} else {
				start = 0;
			}
						
		 	for (int i = start; i < records.size(); i++) {

				record = records.get(i);
				AssociatedObjectsType associatedObjects = new AssociatedObjectsType();
								
				/* saddr (address of responding DNS server) Observable */		
				if (!record.get(SADDR).isEmpty()) {
					WhoisEntry entry = setWhoisEntry(record.get(SADDR), record.get(SORGANIZATION), 
									 record.get(SCOUNTRYCODE), record.get(AUTHORITATIVE_NS));
					associatedObjects		
						.withAssociatedObjects(new AssociatedObjectType()
							.withAssociationType(new ControlledVocabularyStringType()
								.withValue("Address of responding DNS server"))
							.withProperties(entry));
				}

				/* daddr (address of DNS requester) Observable */
				if (!record.get(DADDR).isEmpty()) {
					WhoisEntry entry = setWhoisEntry(record.get(DADDR), record.get(DORGANIZATION), 
									 record.get(DCOUNTRYCODE), "");
					associatedObjects		
						.withAssociatedObjects(new AssociatedObjectType()
							.withAssociationType(new ControlledVocabularyStringType()
								.withValue("Address of DNS requester"))
							.withProperties(entry));
				}

				/* raddr (address of requested DNS) Observable */
				if (!record.get(RADDR).isEmpty()) {
					WhoisEntry entry = setWhoisEntry(record.get(RADDR), record.get(RORGANIZATION), 
									 record.get(RCOUNTRYCODE), "");
					associatedObjects		
						.withAssociatedObjects(new AssociatedObjectType()
							.withAssociationType(new ControlledVocabularyStringType()
								.withValue("Address of requested DNS"))
							.withProperties(entry));
				}	

				/* creating DNS Record */
				DNSRecord dnsRecord = new DNSRecord();
				if (!record.get(LAST_SEEN_TIMET).isEmpty()) {
					dnsRecord
						.withQueriedDate(new DateTimeObjectPropertyType()
							.withValue(record.get(LAST_SEEN_TIMET)));
				}
		
				//if record does not contain rqfqds, then put in refqdn ... or not ???
				if (!record.get(RQFQDN).isEmpty()) {
					dnsRecord
						.withDomainName(setURIObjectType(record.get(RQFQDN)));
				} else {
					if (!record.get(REFQDN).isEmpty()) {
						dnsRecord
							.withDomainName(setURIObjectType(record.get(REFQDN)));
					}
				}
				if (!record.get(RADDR).isEmpty()) {
					dnsRecord
						.withIPAddress(setAddress(record.get(RADDR)));
				}
				if (!record.get(RQTYPE).isEmpty()) {
					dnsRecord
						.withEntryType(new StringObjectPropertyType()
							.withValue(record.get(RQTYPE)));
				}
				if (!record.get(TTL).isEmpty()) {
					dnsRecord
						.withTTL(new IntegerObjectPropertyType()
							.withValue(record.get(TTL)));
				}
				if (!record.get(FLAGS).isEmpty()) {
					dnsRecord
						.withFlags(new HexBinaryObjectPropertyType()
							.withValue(record.get(FLAGS)));
				}

				/* packing record into AssociatedObjectType */
				DNSQuery dnsQuery = new DNSQuery();
				String description = record.get(DADDR) + " requested address of DNS name " + ((!record.get(RQFQDN).isEmpty()) ? record.get(RQFQDN) : record.get(REFQDN));
				if (!record.get(AUTHORITATIVE_NS).isEmpty()) {
					dnsQuery
						.withAuthorityResourceRecords(new DNSResourceRecordsType()
								.withResourceRecords(dnsRecord
									.withDescription(new StructuredTextType()
										.withValue(description))));
				} else {
					if (!record.get(ANSWER_NS).isEmpty()) {
						dnsQuery
							.withAnswerResourceRecords(new DNSResourceRecordsType()
								.withResourceRecords(dnsRecord
									.withDescription(new StructuredTextType()
										.withValue(description))));
					} else {
						dnsQuery
							.withAdditionalRecords(new DNSResourceRecordsType()
								.withResourceRecords(dnsRecord
									.withDescription(new StructuredTextType()
										.withValue(description))));
					}
				} 

				observables
					.withObservables(new Observable()
						.withId(new QName("gov.ornl.stucco", "dnsRecord-" + UUID.randomUUID().toString(), "stucco"))
						.withTitle("DNSRecord")
						.withObservableSources(setMeasureSourceType("DNSRecord"))
						.withEvent(new Event()
							.withActions(new ActionsType()
								.withActions(new ActionType()
									.withAssociatedObjects(associatedObjects
										.withAssociatedObjects(new AssociatedObjectType()
											.withProperties(dnsQuery
												.withTransactionID(new HexBinaryObjectPropertyType()
													.withValue(record.get(RECNUM))))))))));
			}

			return (!observables.getObservables().isEmpty()) ? stixPackage.withObservables(observables) : null;	

		} catch (DatatypeConfigurationException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}

		return null;
	}

	private WhoisEntry setWhoisEntry(String ip, String organization, String countrycode, String authoritation) {
					
		long ipInt = ipToLong(ip);
		Observable ipObservable = setIpObservable(ip, ipInt, "DNSRecord");
		observables
			.withObservables(ipObservable);
		WhoisEntry entry = new WhoisEntry()
			.withIPAddress(new Address()
				.withObjectReference(ipObservable.getId()));
		WhoisContactType contact = new WhoisContactType();
			
		if (!organization.isEmpty()) {
			contact
				.withOrganization(new StringObjectPropertyType()
					.withValue(organization));
		}
		if (!countrycode.isEmpty()) {
			contact
				.withAddress(new StringObjectPropertyType()
					.withValue(countrycode));
		}
		if (!organization.isEmpty() | !countrycode.isEmpty()) {
			entry
				.withContactInfo(contact);
		}
		if (!authoritation.isEmpty()) {
			WhoisNameserversType whoisNameservers = new WhoisNameserversType();
			String[] nameservers = authoritation.split(" ");

			for (int j = 0; j < nameservers.length; j++) {
				whoisNameservers							
					.withNameservers(setURIObjectType(nameservers[j]));
			}
			entry
				.withNameservers(whoisNameservers);
		}

		return entry;
	}
}
