package STIXExtractor;

import javax.xml.namespace.QName;

import java.util.UUID;
import java.util.Iterator;
import java.util.GregorianCalendar;
import java.util.TimeZone;
import java.util.Date;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.Arrays;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import java.io.File;
import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.io.IOException;

import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;

import java.nio.charset.Charset;

import java.text.ParseException;
import java.text.SimpleDateFormat;

import java.math.BigInteger;

import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVRecord;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;

import org.json.*;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Attributes;
import org.jsoup.nodes.Element;
import org.jsoup.parser.Tag;
import org.jsoup.select.Elements;

import org.mitre.stix.stix_1.STIXPackage;
import org.mitre.stix.stix_1.STIXHeaderType;
import org.mitre.stix.common_1.IdentityType;
import org.mitre.stix.common_1.InformationSourceType;
import org.mitre.stix.common_1.ControlledVocabularyStringType;
import org.mitre.stix.common_1.RelatedCourseOfActionType;
import org.mitre.stix.common_1.RelatedTTPType;
import org.mitre.stix.common_1.ToolInformationType;
import org.mitre.stix.courseofaction_1.CourseOfAction;
import org.mitre.stix.indicator_2.Indicator;
import org.mitre.stix.indicator_2.SuggestedCOAsType;
import org.mitre.stix.ttp_1.ToolsType;
import org.mitre.stix.ttp_1.BehaviorType;
import org.mitre.stix.ttp_1.MalwareType;
import org.mitre.stix.ttp_1.MalwareInstanceType;
import org.mitre.stix.ttp_1.TTP;
import org.mitre.cybox.cybox_2.Observables;
import org.mitre.cybox.cybox_2.RelatedObjectType;
import org.mitre.cybox.cybox_2.Observable;
import org.mitre.cybox.cybox_2.ObjectType;
import org.mitre.cybox.cybox_2.KeywordsType;
import org.mitre.cybox.cybox_2.RelatedObjectsType;
import org.mitre.cybox.cybox_2.AssociatedObjectType;
import org.mitre.cybox.cybox_2.AssociatedObjectsType;
import org.mitre.cybox.common_2.Property;
import org.mitre.cybox.common_2.RegionalRegistryType;
import org.mitre.cybox.common_2.NonNegativeIntegerObjectPropertyType;
import org.mitre.cybox.common_2.AnyURIObjectPropertyType;
import org.mitre.cybox.common_2.MeasureSourceType;	
import org.mitre.cybox.common_2.StringObjectPropertyType;
import org.mitre.cybox.common_2.HashType;
import org.mitre.cybox.common_2.SimpleHashValueType;
import org.mitre.cybox.common_2.PositiveIntegerObjectPropertyType;
import org.mitre.cybox.common_2.StructuredTextType;
import org.mitre.cybox.common_2.ConditionTypeEnum;
import org.mitre.cybox.common_2.ConditionApplicationEnum;
import org.mitre.cybox.common_2.CustomPropertiesType;
import org.mitre.cybox.objects.URIObjectType;
import org.mitre.cybox.objects.Address;
import org.mitre.cybox.objects.CategoryTypeEnum;
import org.mitre.cybox.objects.NetworkFlowObject;
import org.mitre.cybox.objects.NetworkFlowLabelType;
import org.mitre.cybox.objects.IANAAssignedIPNumbersType;
import org.mitre.cybox.objects.IANAAssignedIPNumbersTypeEnum;
import org.mitre.cybox.objects.Hostname;
import org.mitre.cybox.objects.Port;
import org.mitre.cybox.objects.SocketAddress;
import org.mitre.cybox.objects.WhoisEntry;
import org.mitre.cybox.objects.UserAccountObjectType;
import org.mitre.cybox.objects.Product;
import org.mitre.cybox.objects.FileObjectType;
import org.mitre.cybox.objects.ProcessObjectType;
import org.mitre.cybox.objects.WindowsRegistryKey;
import org.mitre.cybox.objects.AS;
import org.mitre.cybox.objects.DomainName;
import org.mitre.maec.xmlschema.maec_bundle_4.MalwareActionType;

import org.xml.sax.SAXException;

public abstract class STIXExtractor extends ExtractorUtils {

	private static Set<String> rirSet = new HashSet<String>(Arrays.asList("AFRINIC", "ARIN", "APNIC", "LACNIC", "RIPE"));

	public STIXPackage initStixPackage(String title, String source) throws DatatypeConfigurationException {
		return initStixPackage(title, source, source);	
	}

	public STIXPackage initStixPackage(String title, String id, String source) throws DatatypeConfigurationException {
		GregorianCalendar calendar = new GregorianCalendar();
		XMLGregorianCalendar now = DatatypeFactory.newInstance().newXMLGregorianCalendar(				
			new GregorianCalendar(TimeZone.getTimeZone("UTC")));

		return new STIXPackage()				
 			.withSTIXHeader(new STIXHeaderType()
				.withTitle(title)
				.withInformationSource(new InformationSourceType()
					.withIdentity(new IdentityType()
						.withName(source))))
			.withTimestamp(now)
 			.withId(new QName("gov.ornl.stucco", makeId(id) + "-" + UUID.randomUUID().toString(), "stucco"));
	}
	
	public Observables initObservables() {
		return new Observables()
			.withCyboxMajorVersion("2.0")
			.withCyboxMinorVersion("1.0");
	}

	public TTP initTTP(String source) {
		return initTTP("Malware", source);
	}
	
	public TTP initTTP(String title, String source) {
		return new TTP()
			.withId(new QName("gov.ornl.stucco", makeId(title) + "-" + UUID.randomUUID().toString(), "stucco"))
			.withTitle(title)
			.withInformationSource(new InformationSourceType()
				.withIdentity(new IdentityType()
					.withName(source)));
	}

	public Observable initFlowObservable(String source) {
		return new Observable()
			.withId(new QName("gov.ornl.stucco", "flow-" + UUID.randomUUID().toString(), "stucco"))
			.withTitle("Flow")
			.withObservableSources(setMeasureSourceType(source));
	}

     	public URIObjectType setURIObjectType(String uri) {
     		return new URIObjectType()
        		.withValue(new AnyURIObjectPropertyType()
                		.withValue(uri));
	}

	public MeasureSourceType setMeasureSourceType(String source) {
		return new MeasureSourceType()
                	.withInformationSourceType(new org.mitre.cybox.common_2.ControlledVocabularyStringType()
	                     	.withValue(source));
	}

	public HashType setHashType(String hash, String type) {
		return new HashType()	
			.withType(new org.mitre.cybox.common_2.ControlledVocabularyStringType()
				.withValue(type))
			.withSimpleHashValue(new SimpleHashValueType()
				.withValue(hash));
	}

	public RelatedObjectType setRelatedObjectType(QName idref, String relationship) {
   		return new RelatedObjectType()
                   		.withIdref(idref)
                     		.withRelationship(new org.mitre.cybox.common_2.ControlledVocabularyStringType()
                           	.withValue(relationship));
	}

	public Observable setHostObservable(String hostname, String source) {
		return new Observable()
			.withId(new QName("gov.ornl.stucco", "hostname-" + UUID.randomUUID().toString(), "stucco"))
	            	.withTitle("Host")
                	.withObservableSources(setMeasureSourceType(source))
                      	.withObject(new ObjectType()
                    		.withId(new QName("gov.ornl.stucco", "hostname-" + makeId(hostname), "stucco"))
                                .withDescription(new StructuredTextType()
                      			.withValue(hostname))
                           	.withProperties(new Hostname()
                                	.withHostnameValue(new StringObjectPropertyType()
                                       		.withValue(hostname))));
	}
	
	public Observable setDNSAddressObservable(String dns, QName dnsId, String source) {
		return new Observable()
				.withId(new QName("gov.ornl.stucco", "address-" + UUID.randomUUID().toString(), "stucco"))	
				.withTitle("Address")
				.withObservableSources(setMeasureSourceType(source))
				.withObject(new ObjectType()
					.withId(new QName("gov.ornl.stucco", "address-" + makeId(dns + "_unknown"), "stucco"))
					.withDescription(new org.mitre.cybox.common_2.StructuredTextType()
						.withValue(dns + ", port unknown"))
					.withRelatedObjects(new RelatedObjectsType()
                                       		.withRelatedObjects(setRelatedObject(dnsId,
                                                                        	     "hasDNSName",
                                                                                      dns + ", port unknown has DNSName " + dns,
                                                                                      "Sophos"))));
	}
 
	public Observable setDNSAddressObservable(String port, QName portId, String dns, QName dnsId, String source) {
		return new Observable()
				.withId(new QName("gov.ornl.stucco", "address-" + UUID.randomUUID().toString(), "stucco"))	
				.withTitle("Address")
				.withObservableSources(setMeasureSourceType(source))
				.withObject(new ObjectType()
					.withId(new QName("gov.ornl.stucco", "address-" + makeId(dns + "_" + port), "stucco"))
					.withDescription(new org.mitre.cybox.common_2.StructuredTextType()
						.withValue(dns + ", port " + port)) 
					.withProperties(new SocketAddress()
						.withPort(new Port()
							.withObjectReference(portId)))
					.withRelatedObjects(new RelatedObjectsType()
                                       		.withRelatedObjects(setRelatedObject(dnsId,
                                                                        	     "hasDNSName",
                                                                                      dns + ", port " + port + " has DNSName " + dns,
                                                                                      "Sophos"))));
	}

	public Observable setAddressObservable(String port, QName portId, String description, String source) {
		return new Observable()
				.withId(new QName("gov.ornl.stucco", "address-" + UUID.randomUUID().toString(), "stucco"))	
				.withTitle("Address")
				.withObservableSources(setMeasureSourceType(source))
				.withObject(new ObjectType()
					.withId(new QName("gov.ornl.stucco", "address-" + port, "stucco"))
					.withDescription(new org.mitre.cybox.common_2.StructuredTextType()
						.withValue(description)) 
					.withProperties(new SocketAddress()
						.withPort(new Port()
							.withObjectReference(portId))));
	}
	
	public Observable setAddressObservable(String description, String source) {
		return setAddressObservable(source)
			.withObject(new ObjectType()
				.withDescription(new org.mitre.cybox.common_2.StructuredTextType()
					.withValue(description)));
	}
 
	public Observable setAddressObservable(String source) {
		return new Observable()
				.withId(new QName("gov.ornl.stucco", "address-" + UUID.randomUUID().toString(), "stucco"))	
				.withTitle("Address")
				.withObservableSources(setMeasureSourceType(source));
	}

	public Observable setAddressObservable(String ip, long ipInt, QName ipId, String source) {
		return new Observable()
				.withId(new QName("gov.ornl.stucco", "address-" + UUID.randomUUID().toString(), "stucco"))	
				.withTitle("Address")
				.withObservableSources(setMeasureSourceType(source))
				.withObject(new ObjectType()
					.withId(new QName("gov.ornl.stucco", "address-" + ipToLong(ip), "stucco"))
					.withDescription(new org.mitre.cybox.common_2.StructuredTextType()
						.withValue(ip)) 
					.withProperties(new SocketAddress()
						.withIPAddress(new Address()
							.withObjectReference(ipId))));
	}

	public Observable setAddressObservable(String ip, long ipInt, QName ipId, String port, QName portId, String source) {
		return new Observable()
				.withId(new QName("gov.ornl.stucco", "address-" + UUID.randomUUID().toString(), "stucco"))	
				.withTitle("Address")
				.withObservableSources(setMeasureSourceType(source))
				.withObject(new ObjectType()
					.withId(new QName("gov.ornl.stucco", "address-" + ipToLong(ip) + "_" + port, "stucco"))
					.withDescription(new org.mitre.cybox.common_2.StructuredTextType()
						.withValue(ip + ", port " + port)) 
					.withProperties(new SocketAddress()
						.withIPAddress(new Address()
							.withObjectReference(ipId))
						.withPort(new Port()
							.withObjectReference(portId))));
	}
						
	public Observable setAddressRangeObservable(String startIp, String endIp, String source) {
		return setAddressRangeObservable(startIp, endIp, startIp + " through " + endIp, source);

	}
	
	public Observable setAddressRangeObservable(String startIp, String endIp, String description, String source) {
		return new Observable()
			.withId(new QName("gov.ornl.stucco", "addressRange-" + UUID.randomUUID().toString(), "stucco"))
			.withTitle("AddressRange")
			.withObservableSources(setMeasureSourceType(source))
			.withObject(new ObjectType()
				.withId(new QName("gov.ornl.stucco", "addressRange-" + ipToLong(startIp) + "-" + ipToLong(endIp), "stucco"))
				.withDescription(new org.mitre.cybox.common_2.StructuredTextType()
					.withValue(description))
				.withProperties(new Address()
					.withAddressValue(new StringObjectPropertyType()
						.withValue(startIp + " - " + endIp)
					.withCondition(ConditionTypeEnum.INCLUSIVE_BETWEEN)
					.withApplyCondition(ConditionApplicationEnum.ANY)
					.withDelimiter(" - "))
					.withCategory(CategoryTypeEnum.IPV_4_ADDR)));
	}

	public Observable setAddressRangeObservable(IpUtils ipUtils, String source) {
		return setAddressRangeObservable(ipUtils.getButtomIpAddress(),  ipUtils.getButtomIpBigInt(), ipUtils.getTopIpAddress(), ipUtils.getTopIpBigInt(), source);
	}

	public Observable setAddressRangeObservable(String startIp, BigInteger startIpInt, String endIp, BigInteger endIpInt, String source) {
		return new Observable()
			.withId(new QName("gov.ornl.stucco", "addressRange-" + UUID.randomUUID().toString(), "stucco"))
			.withTitle("AddressRange")
			.withObservableSources(setMeasureSourceType(source))
			.withObject(new ObjectType()								
				.withId(new QName("gov.ornl.stucco", "addressRange-" + startIpInt + "-" + endIpInt, "stucco"))
				.withDescription(new org.mitre.cybox.common_2.StructuredTextType()
					.withValue(startIp + " through " + endIp))
				.withProperties(new Address()
					.withAddressValue(new StringObjectPropertyType()
						.withValue(startIp + " - " + endIp)
					.withCondition(ConditionTypeEnum.INCLUSIVE_BETWEEN)
					.withApplyCondition(ConditionApplicationEnum.ANY)
					.withDelimiter(" - "))
					.withCategory(CategoryTypeEnum.IPV_4_ADDR)));
	}

	public Observable setIpObservable(String ip, long ipInt, String keyword, String source) {
		return setIpObservable(ip, ipInt, source)
			.withKeywords(new KeywordsType()
		                .withKeywords(keyword));
	}
	
	public Observable setIpObservable(String ip, String source) {
		return setIpObservable(ip, ipToLong(ip), source);
	}	

	public Observable setIpObservable(String ip, long ipLong, String source) {
		return new Observable()
				.withId(new QName("gov.ornl.stucco", "ip-" + UUID.randomUUID().toString(), "stucco"))	
				.withTitle("IP")
				.withObservableSources(setMeasureSourceType(source))
				.withObject(new ObjectType()
					.withId(new QName("gov.ornl.stucco", "ip-" + ipLong, "stucco"))
					.withDescription(new org.mitre.cybox.common_2.StructuredTextType()
						.withValue(ip)) 
					.withProperties(setAddress(ip, CategoryTypeEnum.IPV_4_ADDR)));
	}
	
	public Observable setASNObservable(String asn, String asName, String registry, String source) {
		return new Observable()
				.withId(new QName("gov.ornl.stucco", "as-" + UUID.randomUUID().toString(), "stucco"))	
				.withTitle("AS")
				.withObservableSources(setMeasureSourceType(source))
				.withObject(new ObjectType()
					.withId(new QName("gov.ornl.stucco", "as-" + makeId(asName) + "_" + asn, "stucco"))
					.withDescription(new org.mitre.cybox.common_2.StructuredTextType()
						.withValue("AS " + asName + " has ASN " + asn)) 
					.withProperties(new AS()
						.withNumber((asn.isEmpty()) ? null : new NonNegativeIntegerObjectPropertyType()
							.withValue(asn))
						.withName((asName.isEmpty()) ? null : new StringObjectPropertyType()
							.withValue(asName))	
						.withRegionalInternetRegistry((!rirSet.contains(registry)) ? null : new RegionalRegistryType()
							.withValue(registry))));
	}

	public Address setAddress(String address) {
		return new Address()
			.withAddressValue(new StringObjectPropertyType()
				.withValue(address));
	}

	public Address setAddress(String address, CategoryTypeEnum category) {
		return new Address()
			.withAddressValue(new StringObjectPropertyType()
				.withValue(address))
			.withCategory(category);
	}

	public Observable setPortObservable(String port, String source) {
		QName portId = new QName("gov.ornl.stucco", "port-" + UUID.randomUUID().toString(), "stucco");
				
		return new Observable()			//list
				.withId(portId)
				.withTitle("Port")
				.withObservableSources(setMeasureSourceType(source))
				.withObject(new ObjectType()
					.withId(new QName("gov.ornl.stucco", "port-" + port, "stucco"))
					.withDescription(new org.mitre.cybox.common_2.StructuredTextType()
						.withValue(port)) 
					.withProperties(new Port()
						.withPortValue(new PositiveIntegerObjectPropertyType()
							.withValue(port))));
	}

	public Observable setDNSObservable(String dns, String source) {
		return new Observable()
			.withId(new QName("gov.ornl.stucco", "dnsName-" + UUID.randomUUID().toString(), "stucco"))	
			.withTitle("DNSName")
			.withObservableSources(setMeasureSourceType(source))
			.withObject(new ObjectType()
				.withId(new QName("gov.ornl.stucco", "dnsName-" + makeId(dns), "stucco"))
				.withDescription(new org.mitre.cybox.common_2.StructuredTextType()
					.withValue(dns))
				.withProperties(new DomainName()
					.withValue(new StringObjectPropertyType()
						.withValue(dns))));
	}

	public Observable setAccountObservable(String user, String source) {
		return new Observable()
			.withId(new QName("gov.ornl.stucco", "account-" + UUID.randomUUID().toString(), "stucco"))	
			.withTitle("Account")
			.withObservableSources(setMeasureSourceType(source))
			.withObject(new ObjectType()
				.withId(new QName("gov.ornl.stucco", "account-" + makeId(user), "stucco"))
				.withProperties(new UserAccountObjectType()
					.withUsername(new StringObjectPropertyType()
						.withValue(user))
					.withDescription(new StringObjectPropertyType()
						.withValue(user))));
	}
		
	public Observable setSoftwareObservable(String software, String source) {
		return setSoftwareObservable(software, software, source);
	}

	public Observable setSoftwareObservable(String software, String description, String source) {
		return new Observable()
			.withId(new QName("gov.ornl.stucco", "software-" + UUID.randomUUID().toString(), "stucco"))
			.withTitle("Software")
			.withObservableSources(setMeasureSourceType(source))
			.withObject(new ObjectType()
				.withId(new QName("gov.ornl.stucco", "software-" + makeId(software), "stucco"))
				.withDescription(new StructuredTextType()
					.withValue(description))
				.withProperties(new Product()
					.withProduct(new StringObjectPropertyType()
						.withValue(software))));
	}

	public Observable setFlowObservable(String srcIp, String srcPort, QName srcId, String dstIp, String dstPort, QName dstId, String source) {
		return setFlowObservable(srcIp, ipToLong(srcIp), srcPort, srcId, dstIp, ipToLong(dstIp), dstPort, dstId, source);
	}

	public Observable setFlowObservable(String srcIp, long srcIpLong, String srcPort, QName srcId, String dstIp, long dstIpLong, String dstPort, QName dstId, String source) {
		return new Observable()
			.withId(new QName("gov.ornl.stucco", "flow-" + UUID.randomUUID().toString(), "stucco"))
			.withTitle("Flow")
			.withObservableSources(setMeasureSourceType(source))
			.withObject(new ObjectType()
				.withId(new QName("gov.ornl.stucco", "flow-" + srcIpLong + "_" + srcPort + "-" + dstIpLong + "_" + dstPort, "stucco"))
				.withDescription(new org.mitre.cybox.common_2.StructuredTextType()
					.withValue(srcIp + ", port " + srcPort + " to " + dstIp + ", port " + dstPort))
				.withProperties(new NetworkFlowObject()
					.withNetworkFlowLabel(new NetworkFlowLabelType()
						.withSrcSocketAddress(new SocketAddress()
							.withObjectReference(srcId))
						.withDestSocketAddress(new SocketAddress()
							.withObjectReference(dstId))))); 
	}

	public Indicator setMalwareIndicator(String name, String source) {
		return new Indicator()
			.withId(new QName("gov.ornl.stucco", "malware-" + UUID.randomUUID().toString(), "stucco"))
			.withTitle("Malware")
			.withIndicatedTTPs(new RelatedTTPType()
				.withTTP(initTTP("Malware", source)
					.withBehavior(new BehaviorType()
						.withMalware(new MalwareType()
							.withMalwareInstances(setMalwareInstance(name, source))))));
	}
	
	public MalwareInstanceType setMalwareInstance(String name, String source) {
		return setMalwareInstance(name, name, name, source);
	}
													
	public MalwareInstanceType setMalwareInstance(String name, String description, String source) {
		return setMalwareInstance(name, name, description, source);
	}

	public MalwareInstanceType setMalwareInstance(String title, String name, String description, String source) {
		return new MalwareInstanceType()
			.withId(new QName("gov.ornl.stucco", "malware-" + makeId(name), "stucco"))
			.withTitle(title)
			.withTypes(new ControlledVocabularyStringType() 
				.withValue(name))
			.withNames(new ControlledVocabularyStringType() 
				.withValue(name))
			.withDescriptions(new org.mitre.stix.common_1.StructuredTextType()
				.withValue(description));
	}

/*
	public MalwareInstanceType setMalwareInstance(String id, String source) {
		return new MalwareInstanceType()
			.withId(new QName("gov.ornl.stucco", "malware-" + makeId(source + "_" + id), "stucco"))
			.withTypes(new ControlledVocabularyStringType() //list
				.withValue("Malware"))
			.withNames(new ControlledVocabularyStringType() //list
				.withValue(source + "_" + id))
			.withDescriptions(new org.mitre.stix.common_1.StructuredTextType()
				.withValue(source + " entry " + id));
	}
*/

	public RelatedObjectType setRelatedObject(QName idref, String relationship, String description, String source) {
		return new RelatedObjectType() 
			.withIdref(idref)
			.withRelationship(new org.mitre.cybox.common_2.ControlledVocabularyStringType()
				.withValue(relationship))
			.withDescription(new StructuredTextType()
				.withValue(description))
			.withDiscoveryMethod(setMeasureSourceType(source));
	}

	public CourseOfAction setCourseOfAction(String title, String description, String source) {
		return new CourseOfAction()
			.withId(new QName("gov.ornl.stucco", makeId(title) + "-" + UUID.randomUUID().toString(), "stucco"))
			.withTitle(title)
			.withInformationSource(new InformationSourceType()
				.withIdentity(new IdentityType()
					.withName(source)))
			.withDescriptions(new org.mitre.stix.common_1.StructuredTextType()
					.withValue(description));
	}

	public Indicator setMalwareCoaIndicator(String malwareName, QName ttpId, QName coaId, String source) {
		return new Indicator()
			.withId(new QName("gov.ornl.stucco", "malware" + "-" + UUID.randomUUID().toString(), "stucco"))
			.withTitle(malwareName)
		//	.withTypes(new ControlledVocabularyStringType()
		//		.withValue("Malware"))
		//	.withTypes(new ControlledVocabularyStringType() 
		//		.withValue("Solution"))
			.withIndicatedTTPs(new RelatedTTPType()
				.withTTP(new TTP()
					.withIdref(ttpId)))
		//	.withDescriptions(new org.mitre.stix.common_1.StructuredTextType()
		//		.withValue("Describes " + malwareName + " and " + " potential solution."))
			.withSuggestedCOAs(new SuggestedCOAsType()
				.withSuggestedCOAs(new RelatedCourseOfActionType()
					.withCourseOfAction(new CourseOfAction()
						.withIdref(coaId))));
	}
	
	public Indicator setMalwareAddressIndicator(QName ttpId, QName addressId, String source) {
		return new Indicator()
			.withId(new QName("gov.ornl.stucco", "malware" + "-" + UUID.randomUUID().toString(), "stucco"))
			.withTypes(new ControlledVocabularyStringType()
				.withValue("Malware"))
			.withTypes(new ControlledVocabularyStringType() 
				.withValue("Address"))
			.withIndicatedTTPs(new RelatedTTPType()
				.withTTP(new TTP()
					.withIdref(ttpId)))
			.withObservable(new Observable()
				.withIdref(addressId));
	}

	public Property setCustomProperty(String name, Object value) {
		return new Property()
			.withName(name)
			.withValue(value);		
	}		

	public List<AssociatedObjectType> setFiles(Set<String> items) {
		List<AssociatedObjectType> files = new ArrayList<AssociatedObjectType>();

		for (String item: items) {
			files.add(new AssociatedObjectType()
					.withProperties(new FileObjectType()
						.withFileName(new StringObjectPropertyType()
							.withValue(item))));
		}

		return files;
	}

	public HashType setHash(String type, String hash) {
		return new HashType()
			.withType(new org.mitre.cybox.common_2.ControlledVocabularyStringType()
					.withValue(type))
			.withSimpleHashValue(new SimpleHashValueType()
					.withValue(hash));		
	}

	public List<AssociatedObjectType> setProcesses(Set<String> items) {
		List<AssociatedObjectType> processes = new ArrayList<AssociatedObjectType>();

		for (String item: items) {
			processes.add(new AssociatedObjectType()
					.withProperties(new ProcessObjectType()
						.withName(new StringObjectPropertyType()
							.withValue(item))));
		}

		return processes;
	}



	public List<AssociatedObjectType> setRegistryKeys(Set<String> items) {
		List<AssociatedObjectType> registryKeys = new ArrayList<AssociatedObjectType>();

		for (String item: items) {
			registryKeys.add(new AssociatedObjectType()
				.withProperties(new WindowsRegistryKey()
					.withKey(new StringObjectPropertyType()
						.withValue(item))));
		}

		return registryKeys;
	}

	public MalwareActionType setActions(String actionType, String actionDescription, Set<AssociatedObjectType> actionSet) {
		return new MalwareActionType()				
			.withType(new org.mitre.cybox.common_2.ControlledVocabularyStringType()
					.withValue(actionType))
			.withDescription(new org.mitre.cybox.common_2.StructuredTextType()
					.withValue(actionDescription))	
			.withAssociatedObjects(new AssociatedObjectsType()
					.withAssociatedObjects(actionSet));
	}

	public ToolsType setTools(String type, Set<String> newItems) {
		ToolsType tools = new ToolsType();

		for (String item: newItems) {
			tools
				.withTools(new ToolInformationType()
					.withName(item)					
					.withTypes(new org.mitre.cybox.common_2.ControlledVocabularyStringType()
						.withValue(type)));
		}

		return tools;
	}

	boolean validate(STIXPackage stixPackage) {
		try {
			return stixPackage.validate();
		} catch (SAXException e) {
			e.printStackTrace();
		}

		return false;
	}
}

