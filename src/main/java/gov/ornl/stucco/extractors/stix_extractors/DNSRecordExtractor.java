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
import org.mitre.cybox.objects.WhoisRegistrantsType;
import org.mitre.cybox.objects.WhoisRegistrantInfoType;
import org.mitre.cybox.objects.URIObjectType;

/**
 * DNS record to STIX format extractor.
 *
 * @author Maria Vincent
 */
public class DNSRecordExtractor extends STIXUtils {
						
	private static final Logger logger = LoggerFactory.getLogger(DNSRecordExtractor.class);
	private static String[] HEADERS = {"filename", "recnum", "file_type", "amp_version", "site", "saddr", "daddr", "ttl", "rqtype", "flags", "rqfqdn",
					   "refqdn", "raddr", "preference", "answer_ns", "authoritative_ns", "times_seen", "first_seen_timet", "last_seen_timet", 
					   "scountrycode", "sorganization", "dcountrycode", "dorganization", "rcountrycode", "rorganization"};
	private static final String FILENAME = "filename";	
	private static final String SADDR = "saddr";	
	private static final String DADDR = "daddr";	
	private static final String TTL = "ttl";	
	private static final String RQTYPE = "rqtype";	
	private static final String FLAGS = "flags";	
	private static final String RQFQDN = "rqfqdn";	
	private static final String RADDR = "raddr";	
	private static final String LAST_SEEN_TIMET = "last_seen_timet";	

	private STIXPackage stixPackage;
	private Observables observables;
	
	public DNSRecordExtractor(String dnsInfo) {
		stixPackage = extract(dnsInfo);
	}
					
	public STIXPackage getStixPackage() {
		return stixPackage;
	}

	private STIXPackage extract (String dnsInfo) {
		List<CSVRecord> records;
		try {
			records = getCSVRecordsList(HEADERS, dnsInfo);
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
				if (record.get(RQFQDN).isEmpty() && record.get(RADDR).isEmpty()) {
					continue;
				}
				
				Observable srcIpObservable = null;
				Observable dstIpObservable = null;
				Observable rIpObservable = null;
				Observable rDnsObservable = null;
								
				/* saddr (address of responding DNS server) Observable */		
				if (!record.get(SADDR).isEmpty()) {
					srcIpObservable = setIpObservable(record.get(SADDR),ipToLong(record.get(SADDR)), "DNSRecord");
					observables
						.withObservables(srcIpObservable);
				}

				/* daddr (address of DNS requester) Observable */
				if (!record.get(DADDR).isEmpty()) {
					dstIpObservable = setIpObservable(record.get(DADDR),ipToLong(record.get(DADDR)), "DNSRecord");
					observables
						.withObservables(dstIpObservable);
				}

				/* raddr (requested address) Observable */
				if (!record.get(RADDR).isEmpty()) {
					rIpObservable = setIpObservable(record.get(RADDR),ipToLong(record.get(RADDR)), "DNSRecord");
					observables 
						.withObservables(rIpObservable);
				}
				
				/* DNSName observable */
				if (!record.get(RQFQDN).isEmpty()) {
					rDnsObservable = setDNSObservable(record.get(RQFQDN), "DNSRecord");
					observables 
						.withObservables(rDnsObservable);
				}

				/* DNS Record */
				DNSRecord dnsRecord = new DNSRecord()
					.withDescription(new StructuredTextType()
						.withValue("Requested domain name " + record.get(RQFQDN) + " resolved to IP address " + record.get(RADDR)))
					.withQueriedDate((record.get(LAST_SEEN_TIMET).isEmpty()) ? null : new DateTimeObjectPropertyType()
						.withValue(record.get(LAST_SEEN_TIMET)))
					.withDomainName((rDnsObservable == null) ? null : new URIObjectType()
						.withObjectReference(rDnsObservable.getId()))
					.withIPAddress((rIpObservable == null) ? null : new Address()
						.withObjectReference(rIpObservable.getId()))
					.withEntryType((record.get(RQTYPE).isEmpty()) ? null : new StringObjectPropertyType()
						.withValue(record.get(RQTYPE)))
					.withTTL((record.get(TTL).isEmpty()) ? null : new IntegerObjectPropertyType()
						.withValue(record.get(TTL)))
					.withFlags((record.get(FLAGS).isEmpty()) ? null : new HexBinaryObjectPropertyType()
						.withValue(record.get(FLAGS)));

				/* packing record into Observable */
				observables
					.withObservables(new Observable()
						.withId(new QName("gov.ornl.stucco", "dnsRecord-" + UUID.randomUUID().toString(), "stucco"))
						.withTitle("DNSRecord")
						.withObservableSources(setMeasureSourceType("DNSRecord"))
						.withObject(new ObjectType()
							.withProperties(dnsRecord)
							.withRelatedObjects(new RelatedObjectsType()
								.withRelatedObjects((dstIpObservable == null) ? null : setRelatedObject(dstIpObservable.getId()))
								.withRelatedObjects((srcIpObservable == null) ? null : setRelatedObject(srcIpObservable.getId())))));
			} catch (RuntimeException e) {
				e.printStackTrace();
			}
		}

		if (!observables.getObservables().isEmpty()) {
			try {
				stixPackage = initStixPackage("DNS Record", "DNSRecord")
					.withObservables(observables);	
			}	catch (DatatypeConfigurationException e) {
				e.printStackTrace();
			}
		}
		return stixPackage;
	}
}

