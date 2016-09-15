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
import org.mitre.cybox.cybox_2.ObjectType;
import org.mitre.cybox.cybox_2.RelatedObjectsType;
import org.mitre.cybox.cybox_2.RelatedObjectType;
import org.mitre.cybox.common_2.StringObjectPropertyType;
import org.mitre.cybox.common_2.IntegerObjectPropertyType;
import org.mitre.cybox.common_2.DateTimeObjectPropertyType;
import org.mitre.cybox.common_2.AnyURIObjectPropertyType;
import org.mitre.cybox.common_2.ControlledVocabularyStringType;
import org.mitre.cybox.objects.Port;
import org.mitre.cybox.objects.HTTPSession;
import org.mitre.cybox.objects.HTTPRequestResponseType;
import org.mitre.cybox.objects.HTTPClientRequestType;
import org.mitre.cybox.objects.HTTPRequestLineType;
import org.mitre.cybox.objects.HTTPMethodType;
import org.mitre.cybox.objects.HTTPRequestHeaderType;
import org.mitre.cybox.objects.HTTPRequestHeaderFieldsType;
import org.mitre.cybox.objects.Address;
import org.mitre.cybox.objects.HostFieldType;
import org.mitre.cybox.objects.URIObjectType;
import org.mitre.cybox.objects.Port;

/**
 * CPP HTTP data to STIX format extractor.
 *
 * @author Maria Vincent
 */
public class HTTPDataExtractor extends STIXUtils {
						
	private static final Logger logger = LoggerFactory.getLogger(ServiceListExtractor.class);
	private static String[] HEADERS = {"filename", "recnum", "file_type", "amp_version", "site", "saddr", "daddr", "request_len", "dport", "times_seen", "first_seen_timet",	
					"last_seen_timet", "method", "request", "query_terms", "accept_language", "user_agent", "server_fqdn", "referer", "uri", "clean_data", 
					"full_data", "scountrycode", "sorganization", "slat", "slong", "dcountrycode", "dorganization", "dlat", "dlong", "distance"}; 
	static final String FILENAME = "filename";
	static final String AMP_VERSION = "amp_version";
	static final String SADDR = "saddr";
	static final String REQUEST_LEN = "request_len";
	static final String DPORT = "dport";
	static final String LAST_SEEN_TIMET = "last_seen_timet";
	static final String METHOD = "method";
	static final String REQUEST = "request";
	static final String ACCEPT_LANGUAGE = "accept_language";
	static final String USER_AGENT = "user_agent";
	static final String SERVER_FQDN = "server_fqdn";
	static final String REFERER = "referer";
	static final String FULL_DATA = "full_data";
	static final String DADDR = "daddr";		
	
	private STIXPackage stixPackage;
	private Observables observables;
	
	public HTTPDataExtractor(String httpInfo) {
		stixPackage = extract(httpInfo);
	}
					
	public STIXPackage getStixPackage() {
		return stixPackage;
	}

	private STIXPackage extract (String httpInfo) {
		List<CSVRecord> records;
		try {
			records = getCSVRecordsList(HEADERS, httpInfo);
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

				if (record.get(SADDR).isEmpty() && record.get(DADDR).isEmpty() && record.get(SERVER_FQDN).isEmpty() && record.get(REQUEST).isEmpty()) {
					continue;
				}

				Observable srcIpObservable = null;
				Observable dstIpObservable = null;
				Observable dstPortObservable = null;
				Observable domainNameObservable = null;
			
				if (!record.get(SADDR).isEmpty()) {
					srcIpObservable = setIpObservable(record.get(SADDR), "HTTPRequest");
					observables
						.withObservables(srcIpObservable);
				}
				if (!record.get(DADDR).isEmpty()) {
					dstIpObservable = setIpObservable(record.get(DADDR), "HTTPRequest");
					observables
						.withObservables(dstIpObservable);
				}
				if (!record.get(DPORT).isEmpty()) {
					dstPortObservable = setPortObservable(record.get(DPORT), "HTTPRequest");
					observables
						.withObservables(dstPortObservable);
				}
				if (!record.get(SERVER_FQDN).isEmpty()) {
					domainNameObservable = setDNSObservable(record.get(SERVER_FQDN), "HTTPRequest");
					if (dstIpObservable != null) {
						domainNameObservable
							.getObject()
								.withRelatedObjects(new RelatedObjectsType()
									.withRelatedObjects(new RelatedObjectType()
										.withRelationship(new ControlledVocabularyStringType()
											.withValue("Resolved_To"))
										.withIdref(dstIpObservable.getId())));
					}
					observables
						.withObservables(domainNameObservable);
				}

				Observable httpRequestObservable = new Observable()
					.withId(new QName("gov.ornl.stucco", "httpRequest-" + UUID.randomUUID().toString(), "stucco"))	
					.withTitle("HTTPRequest")
					.withObservableSources(setMeasureSourceType("HTTPRequest"))
					.withObject(new ObjectType()
						.withDescription(new org.mitre.cybox.common_2.StructuredTextType()
							.withValue("HTTP request of URL " + record.get(REQUEST)))
						.withProperties(new HTTPSession() 
							.withHTTPRequestResponses(new HTTPRequestResponseType()
								.withHTTPClientRequest(new HTTPClientRequestType()
									.withHTTPRequestLine(new HTTPRequestLineType()
										.withHTTPMethod((record.get(METHOD).isEmpty()) ? null : new HTTPMethodType()
											.withValue(record.get(METHOD)))
										.withValue((record.get(REQUEST).isEmpty()) ? null : new StringObjectPropertyType()
											.withValue(record.get(REQUEST)))
										.withVersion((record.get(AMP_VERSION).isEmpty()) ? null : new StringObjectPropertyType()
											.withValue(record.get(AMP_VERSION))))
									.withHTTPRequestHeader(new HTTPRequestHeaderType()
										.withRawHeader((record.get(FULL_DATA).isEmpty()) ? null : new StringObjectPropertyType()
											.withValue(record.get(FULL_DATA)))
										.withParsedHeader(new HTTPRequestHeaderFieldsType()
											.withAcceptLanguage((record.get(ACCEPT_LANGUAGE).isEmpty()) ? null : new StringObjectPropertyType()
												.withValue(record.get(ACCEPT_LANGUAGE)))
											.withContentLength((record.get(REQUEST_LEN).isEmpty()) ? null : new IntegerObjectPropertyType()
												.withValue(record.get(REQUEST_LEN)))
											.withDate((record.get(LAST_SEEN_TIMET).isEmpty()) ? null : new DateTimeObjectPropertyType()
												.withValue(record.get(LAST_SEEN_TIMET)))
											.withFrom((srcIpObservable == null) ? null : new Address() 
												.withObjectReference(srcIpObservable.getId()))
											.withHost(new HostFieldType()	
												.withDomainName((record.get(SERVER_FQDN).isEmpty()) ? null : new URIObjectType()
													.withObjectReference(domainNameObservable.getId()))
												.withPort((dstPortObservable == null) ? null : new Port()
													.withObjectReference(dstPortObservable.getId())))
											.withReferer((record.get(REFERER).isEmpty()) ? null : new URIObjectType()	
												.withValue(new AnyURIObjectPropertyType()
													.withValue(record.get(REFERER))))
											.withUserAgent((record.get(USER_AGENT).isEmpty()) ? null : new StringObjectPropertyType()
												.withValue(record.get(USER_AGENT)))))))));
				observables
					.withObservables(httpRequestObservable);
			} catch (RuntimeException e) {
				e.printStackTrace();
			}		
		}

		if (!observables.getObservables().isEmpty()) {
			try {
				stixPackage = initStixPackage("HTTPRequest", "HTTPRequest")
					.withObservables(observables);
			} catch (DatatypeConfigurationException e) {
				e.printStackTrace();
			}
		}

		return stixPackage;		
	}
}
