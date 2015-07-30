package STIXExtractor;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Map;
import java.util.HashMap;
import java.util.List;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.TimeZone;
import java.util.UUID;

import java.text.*;

import org.json.*;
import org.jsoup.*;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.namespace.QName;					
import javax.xml.parsers.ParserConfigurationException;

import org.mitre.stix.stix_1.STIXPackage;
import org.mitre.stix.stix_1.STIXHeaderType;
import org.mitre.stix.stix_1.IndicatorsType;
import org.mitre.stix.common_1.ExploitTargetsType;
import org.mitre.stix.common_1.StructuredTextType;
import org.mitre.stix.common_1.DateTimeWithPrecisionType;
import org.mitre.stix.common_1.ControlledVocabularyStringType;
import org.mitre.stix.common_1.RelatedPackageRefsType;
import org.mitre.stix.common_1.RelatedPackageRefType;
import org.mitre.stix.common_1.RelatedExploitTargetType; 
import org.mitre.stix.common_1.RelatedObservableType;
import org.mitre.stix.common_1.ReferencesType;
import org.mitre.stix.common_1.ToolInformationType;
import org.mitre.stix.common_1.RelatedTTPType;
import org.mitre.stix.common_1.IndicatorBaseType;
import org.mitre.stix.common_1.IdentityType;
import org.mitre.stix.common_1.InformationSourceType;
import org.mitre.stix.exploittarget_1.ExploitTarget;
import org.mitre.stix.exploittarget_1.VulnerabilityType;
import org.mitre.stix.exploittarget_1.CVSSVectorType;
import org.mitre.stix.exploittarget_1.AffectedSoftwareType ;
import org.mitre.stix.ttp_1.ResourceType;
import org.mitre.stix.ttp_1.ToolsType;
import org.mitre.stix.ttp_1.MalwareInstanceType;
import org.mitre.stix.ttp_1.MalwareType;
import org.mitre.stix.ttp_1.BehaviorType;
import org.mitre.stix.ttp_1.TTP;
import org.mitre.stix.indicator_2.Indicator;
import org.mitre.cybox.common_2.MeasureSourceType;
import org.mitre.cybox.common_2. StringObjectPropertyType;
import org.mitre.cybox.common_2.HashListType;
import org.mitre.cybox.common_2.HashType;
import org.mitre.cybox.common_2.SimpleHashValueType;
import org.mitre.cybox.common_2.PositiveIntegerObjectPropertyType;
import org.mitre.cybox.common_2.AnyURIObjectPropertyType;
import org.mitre.cybox.common_2.ConditionTypeEnum;
import org.mitre.cybox.common_2.Property;
import org.mitre.cybox.common_2.CustomPropertiesType;
import org.mitre.cybox.common_2.ConditionTypeEnum;
import org.mitre.cybox.common_2.ConditionApplicationEnum;
import org.mitre.cybox.common_2.LocationType;
import org.mitre.cybox.cybox_2.RelatedObjectsType;
import org.mitre.cybox.cybox_2.Observables;
import org.mitre.cybox.cybox_2.Observables;
import org.mitre.cybox.cybox_2.Observable;
import org.mitre.cybox.cybox_2.ObjectType;
import org.mitre.cybox.objects.Product;
import org.mitre.cybox.objects.CategoryTypeEnum;
import org.mitre.cybox.objects.Address;
import org.mitre.cybox.objects.Port;
import org.mitre.cybox.objects.URIObjectType;
import org.mitre.cybox.objects.DNSRecord;
import org.mitre.cybox.objects.WhoisEntry;
import org.mitre.cybox.objects.WhoisNameserversType;

import org.xml.sax.SAXException;			

public class CleanMxVirusExtractor extends HTMLExtractor	{
							
	private STIXPackage stixPackage;
	private static final Logger logger = LoggerFactory.getLogger(CleanMxVirusExtractor.class);
										
	public CleanMxVirusExtractor(String cleanMxInfo)	{
		stixPackage = extract(cleanMxInfo);
	}
					
	public STIXPackage getStixPackage() {
		return stixPackage;
	}

	private STIXPackage extract (String cleanMxInfo)	{
		
		try	{
			GregorianCalendar calendar = new GregorianCalendar();
			XMLGregorianCalendar now = DatatypeFactory.newInstance().newXMLGregorianCalendar(				
				new GregorianCalendar(TimeZone.getTimeZone("UTC")));
			stixPackage = new STIXPackage()				
 				.withSTIXHeader(new STIXHeaderType().
					withTitle("CleanMx_virus")) 
				.withTimestamp(now)
	 			.withId(new QName("gov.ornl.stucco", "CleanMx_virus-" + UUID.randomUUID().toString(), "stucco"));
			IndicatorsType indicators = new IndicatorsType();
			Observables observables = new Observables()
				.withCyboxMajorVersion("2.0")
				.withCyboxMinorVersion("1.0");

			Document doc = Jsoup.parse(cleanMxInfo);
			Elements entries = doc.select("entry");

			for (Element entry : entries)	{	
				
				QName malwareId = null;
				QName addressId = null;
				QName ipId = null;
				QName portId = null;
				QName dnsId = null;
				QName addressRangeId = null;

				Indicator malwareIndicator = null;
				Observable addressObservable = null;
				Observable ipObservable = null;
				Observable portObservable = null;
				Observable dnsObservable = null;
				Observable addressRangeObservable = null;
//malware		

				if (entry.select("id").hasText())	{
					
					malwareId = new QName("gov.ornl.stucco", "malware-" + UUID.randomUUID().toString(), "stucco");
					malwareIndicator = new Indicator();
					TTP ttp = new TTP();
					MalwareInstanceType malwareInstance = new MalwareInstanceType();
					String id = "CleanMx_" + entry.select("id").text();
					
					malwareInstance
						.withId(new QName(id))
						.withTypes(new ControlledVocabularyStringType() //list
							.withValue("Malware"))
						.withNames(new ControlledVocabularyStringType() //list
							.withValue(id))
						.withDescriptions(new StructuredTextType()
							.withValue("CleanMx entry " + entry.select("id").text()));

					if (entry.select("virusname").hasText())	

						malwareInstance
							.withNames(new ControlledVocabularyStringType() //list
								.withValue(entry.select("virusname").text()));
			

					if (entry.select("md5").hasText())
				
						ttp
							.withId(malwareId)
							.withResources(new ResourceType()
								.withTools(new ToolsType()
									.withTools(new ToolInformationType()	//list
										.withToolHashes(new HashListType()
											.withHashes(getHashType(entry.select("md5").text(), "md5"))))));
					ttp
						.withTitle("Malware")
						.withInformationSource(new InformationSourceType()
							.withIdentity(new IdentityType()
								.withName("CleanMx(virus)")))
						.withBehavior(new BehaviorType()
							.withMalware(new MalwareType()
								.withMalwareInstances(malwareInstance)));
					malwareIndicator
						.withId(malwareId)
						.withIndicatedTTPs(new RelatedTTPType()
							.withTTP(ttp));
				}
//address
	
				if (entry.select("ip").hasText())	{
					
					addressId = new QName("gov.ornl.stucco", "address-" + UUID.randomUUID().toString(), "stucco");	
					addressObservable = new Observable();
					String address  = entry.select("ip").text()  + ":80";
															
					addressObservable 
						.withId(addressId)
						.withTitle("Address")
						.withObservableSources(getMeasureSourceType("CleanMx(virus)"))
						.withObject(new ObjectType()
							.withDescription(new org.mitre.cybox.common_2.StructuredTextType()
								.withValue(entry.select("ip").text() + ", port 80")) 
							.withProperties(getAddress(address, CategoryTypeEnum.IPV_4_ADDR)));
				}

//port 
				portId = new QName("gov.ornl.stucco", "port-" + UUID.randomUUID().toString(), "stucco");
				//TODO extract port from url string, if present
				String port = "80";
				
				portObservable = new Observable()			//list
					.withId(portId)
					.withTitle("Port")
					.withObservableSources(getMeasureSourceType("CleanMx(virus)"))
					.withObject(new ObjectType()
						.withDescription(new org.mitre.cybox.common_2.StructuredTextType()
							.withValue(port)) 
						.withProperties(new Port()
							.withPortValue(new PositiveIntegerObjectPropertyType()
								.withValue(port))));

//DNS
				if (entry.select("domain").hasText())	{
					
					dnsId = new QName("gov.ornl.stucco", "dns-" + UUID.randomUUID().toString(), "stucco");
					String dns = entry.select("domain").text();
					dnsObservable = new Observable();
					WhoisEntry dnsEntry = new WhoisEntry()
						.withDomainName(getURIObjectType(dns));
					WhoisNameserversType ns = new WhoisNameserversType();

					if (entry.select("ns1").hasText())
						ns												
							.withNameservers(getURIObjectType(entry.select("ns1").text()));
				
					if (entry.select("ns2").hasText())
						ns												
							.withNameservers(getURIObjectType(entry.select("ns2").text()));

					if (entry.select("ns3").hasText())
						ns												
							.withNameservers(getURIObjectType(entry.select("ns3").text()));
				
					if (entry.select("ns4").hasText())
						ns												
							.withNameservers(getURIObjectType(entry.select("ns4").text()));
				
					if (entry.select("ns5").hasText())
						ns												
							.withNameservers(getURIObjectType(entry.select("ns5").text()));

					dnsObservable 
						.withId(dnsId)
						.withTitle("DNSName")
						.withObservableSources(getMeasureSourceType("CleanMx(virus)"))
						.withObject(new ObjectType()
							.withDescription(new org.mitre.cybox.common_2.StructuredTextType()
								.withValue(dns))
							.withProperties(new WhoisEntry()
								.withDomainName(getURIObjectType(dns))
								.withNameservers(ns)));
				}
//IP
				if (entry.select("ip").hasText())	{
					
					ipId = new QName("gov.ornl.stucco", "ip-" + UUID.randomUUID().toString(), "stucco");
					String ip = entry.select("ip").text();

					ipObservable = new Observable()
						.withId(ipId)
						.withTitle("IP")
						.withObservableSources(getMeasureSourceType("CleanMx(virus)"))
						.withObject(new ObjectType()
							.withDescription(new org.mitre.cybox.common_2.StructuredTextType()
								.withValue(ip)) 
							.withProperties(getAddress(ip, CategoryTypeEnum.IPV_4_ADDR)));
				}

//address range: missing assignedBy field

				if (entry.select("inetnum").hasText())	{
				
					addressRangeId = new QName("gov.ornl.stucco", "addressRangeId-" + UUID.randomUUID().toString(), "stucco");
					String[] ips = entry.select("inetnum").text().split(" - ");
					String id = ips[0] + "_through_" + ips[1];		

					ObjectType addressRangeObject = new ObjectType();
				
					if (entry.select("country").hasText())
						addressRangeObject
							.withLocation(new LocationType()
								.withName(entry.select("country").text()));

					if (entry.select("netname").hasText() || entry.select("descr").hasText())
						addressRangeObject
							.withDescription(new org.mitre.cybox.common_2.StructuredTextType()
								.withValue("Netname " + entry.select("netname").text() + ": " + entry.select("descr").text())); 
				
					addressRangeObservable = new Observable()
						.withId(addressRangeId)
						.withTitle("AddressRange")
						.withObservableSources(getMeasureSourceType("CleanMx(virus)"))
						.withObject(addressRangeObject
							.withProperties(new Address()
								.withAddressValue(new StringObjectPropertyType()
									.withValue(ips[0] + " - " + ips[1])
								.withCondition(ConditionTypeEnum.INCLUSIVE_BETWEEN)
								.withApplyCondition(ConditionApplicationEnum.ANY)
									.withDelimiter(" - "))
								.withCategory(CategoryTypeEnum.IPV_4_ADDR)));
				}
//relations (edges)

				RelatedObjectsType addressRelatedObjects = new RelatedObjectsType();
				RelatedObjectsType ipRelatedObjects = new RelatedObjectsType();

				if (malwareId != null && addressId != null)	{

					malwareIndicator
						.withObservable(new Observable()
							.withIdref(addressId));
					indicators
						.withIndicators(malwareIndicator);
				}
			
				if (addressId != null)	{


					if (portId != null)	{
						addressRelatedObjects
							.withRelatedObjects(setRelatedObjectType(portId, "address has port"));
						observables
							.withObservables(portObservable);

					}
		
					if (dnsId != null)	{
						addressRelatedObjects
							.withRelatedObjects(setRelatedObjectType(dnsId, "address has DNS Name"));
						observables
							.withObservables(dnsObservable);
					}

					if (ipId != null)	{
						addressRelatedObjects
							.withRelatedObjects(setRelatedObjectType(ipId, "address has IP"));
	
						if (addressRangeId != null)	{
							ipRelatedObjects
								.withRelatedObjects(setRelatedObjectType(addressRangeId, "IP is in address range"));
							observables
								.withObservables(addressRangeObservable);
						}

						ipObservable
							.getObject()
								.withRelatedObjects(ipRelatedObjects);					

						observables
							.withObservables(ipObservable);
					}
					
					addressObservable
						.getObject()
							.withRelatedObjects(addressRelatedObjects);

					observables
						.withObservables(addressObservable);
				}

			}

			if (!indicators.getIndicators().isEmpty())
				stixPackage
					.withIndicators(indicators);
			if (!observables.getObservables().isEmpty())
				stixPackage
					.withObservables(observables);

		} catch (DatatypeConfigurationException e)	{
			e.printStackTrace();
		}

		return stixPackage;
	}
	
	boolean validate(STIXPackage stixPackage) {
		
		try	{
			return stixPackage.validate();
		}			
		catch (SAXException e)	{
			e.printStackTrace();
		}
		return false;
	}
}
