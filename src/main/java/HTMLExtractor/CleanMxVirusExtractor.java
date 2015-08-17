package STIXExtractor;

import java.util.UUID;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.namespace.QName;					

import org.mitre.stix.stix_1.STIXPackage;
import org.mitre.stix.stix_1.STIXHeaderType;
import org.mitre.stix.stix_1.IndicatorsType;
import org.mitre.stix.indicator_2.Indicator;
import org.mitre.stix.ttp_1.TTP;
import org.mitre.stix.ttp_1.MalwareInstanceType;
import org.mitre.stix.ttp_1.ResourceType;
import org.mitre.stix.ttp_1.ToolsType;
import org.mitre.stix.ttp_1.BehaviorType;
import org.mitre.stix.ttp_1.MalwareType;
import org.mitre.stix.common_1.IndicatorBaseType;
import org.mitre.stix.common_1.ControlledVocabularyStringType;
import org.mitre.stix.common_1.ToolInformationType;
import org.mitre.stix.common_1.RelatedObservableType;
import org.mitre.stix.common_1.RelatedTTPType;
import org.mitre.cybox.common_2.LocationType;
import org.mitre.cybox.common_2.HashListType;
import org.mitre.cybox.cybox_2.Observable;
import org.mitre.cybox.cybox_2.RelatedObjectsType;
import org.mitre.cybox.cybox_2.Observables;
import org.mitre.cybox.objects.WhoisNameserversType;
import org.mitre.cybox.objects.WhoisEntry;

/**
 * Clean Mx Virus data to STIX format extractor
 *
 * @author Maria Vincent
 */
public class CleanMxVirusExtractor extends HTMLExtractor {
							
	private STIXPackage stixPackage;
	private static final Logger logger = LoggerFactory.getLogger(CleanMxVirusExtractor.class);
										
	public CleanMxVirusExtractor(String cleanMxInfo) {
		stixPackage = extract(cleanMxInfo);
	}
					
	public STIXPackage getStixPackage() {
		return stixPackage;
	}

	private STIXPackage extract (String cleanMxInfo) {
		try	{
			stixPackage = initStixPackage("CleanMx_virus");				
			Observables observables = initObservables();
			IndicatorsType indicators = new IndicatorsType();

			Document doc = Jsoup.parse(cleanMxInfo);
			Elements entries = doc.select("entry");
			
			if (entries.size() == 0) {
				return null;
			}

			for (Element entry : entries) {	

				Indicator malwareIndicator = null;
				Observable addressObservable = null;
				Observable ipObservable = null;
				Observable portObservable = null;
				Observable dnsObservable = null;
				Observable addressRangeObservable = null;
				String ip = null;
				String[] ips = null;
				String port = null;
				String dns = null;
				long ipInt = 0;

				/* malware observable */		
				if (entry.select("id").hasText()) {
					
					malwareIndicator = new Indicator();
					TTP ttp = initTTP("CleanMx(virus)");
					MalwareInstanceType malwareInstance = setMalwareInstance(entry.select("id").text(), "CleanMx");

					//if additional names are given, adding them
					if (entry.select("virusname").hasText()) {	
						malwareInstance
							.withNames(new ControlledVocabularyStringType() //list
								.withValue(entry.select("virusname").text()));
					}

					//if hash is given, adding it
					if (entry.select("md5").hasText()) {
						ttp
							.withResources(new ResourceType()
								.withTools(new ToolsType()
									.withTools(new ToolInformationType()	//list
										.withToolHashes(new HashListType()
											.withHashes(getHashType(entry.select("md5").text(), "md5"))))));
					}
					
					//packing everything into malware indicator
					malwareIndicator
						.withId(new QName("gov.ornl.stucco", "malware-" + UUID.randomUUID().toString(), "stucco"))
						.withIndicatedTTPs(new RelatedTTPType()
							.withTTP(ttp
								.withBehavior(new BehaviorType()
									.withMalware(new MalwareType()
										.withMalwareInstances(malwareInstance)))));
				}
				
				/* IP observable */
				if (entry.select("ip").hasText()) {
					ip = entry.select("ip").text();
					ipInt = ipToLong(ip);
					ipObservable = setIpObservable(ip, ipInt, "CleanMx(virus)");
				}
				
				/* port observable */ 
				//TODO extract port from url string, if present
				port = "80";
				portObservable = setPortObservable(port, "CleanMx(virus)");
				observables
					.withObservables(portObservable);			
			
				/* address observable */
				if (entry.select("ip").hasText()) {
					addressObservable = setAddressObservable(ip, ipInt, ipObservable.getId(), port, portObservable.getId(), "CleanMx(virus)");
				}

				/* DNS observable */
				if (entry.select("domain").hasText()) {
					
					dns = entry.select("domain").text();
					dnsObservable = setDNSObservable(dns, "CleanMx(virus)");
					WhoisNameserversType ns = new WhoisNameserversType();

					if (entry.select("ns1").hasText()) {
						ns												
							.withNameservers(getURIObjectType(entry.select("ns1").text()));
					}
					if (entry.select("ns2").hasText()) {
						ns												
							.withNameservers(getURIObjectType(entry.select("ns2").text()));
					}
					if (entry.select("ns3").hasText()) {
						ns												
							.withNameservers(getURIObjectType(entry.select("ns3").text()));
					}
					if (entry.select("ns4").hasText()) {
						ns												
							.withNameservers(getURIObjectType(entry.select("ns4").text()));
					}
					if (entry.select("ns5").hasText()) {
						ns												
							.withNameservers(getURIObjectType(entry.select("ns5").text()));
					}
					if (!ns.getNameservers().isEmpty()) {
						((WhoisEntry) dnsObservable 
						 	.getObject()
								.getProperties())
									.withNameservers(ns);
					}
					observables
						.withObservables(dnsObservable);
				}

				/* address range observable (missing assignedBy field) */
				if (entry.select("inetnum").hasText()
					&& entry.select("inetnum").text().matches("\\d{1,3}.\\d{1,3}.\\d{1,3}.\\d{1,3}\\s*-\\s*\\d{1,3}.\\d{1,3}.\\d{1,3}.\\d{1,3}")) {
					ips = entry.select("inetnum").text().split("-");
					ips[0] = ips[0].trim();
					ips[1] = ips[1].trim();
					String id = ips[0] + "_through_" + ips[1];		

					// if description is not provided, then construct it 
					if (entry.select("netname").hasText() || entry.select("descr").hasText()) {
						addressRangeObservable = setAddressRangeObservable(ips[0], ips[1], 
							"Netname " + entry.select("netname").text() + ": " + entry.select("descr").text(), "CleanMx(virus)");
					} else {
 						addressRangeObservable = setAddressRangeObservable(ips[0], ips[1], "CleanMx(virus)");
					}
					if (entry.select("country").hasText()) {
						addressRangeObservable
							.getObject()
								.withLocation(new LocationType()
									.withName(entry.select("country").text()));
					}
					observables
						.withObservables(addressRangeObservable);
				}
			
				/* IP -> addressRange */
				if (ipObservable != null && addressRangeObservable != null) {
					ipObservable
						.getObject()
							.withRelatedObjects(new RelatedObjectsType()
								.withRelatedObjects(setRelatedObject(addressRangeObservable.getId(), 
												     "IP is in address range",
												     ip + " is in address range " + ips[0] + " through " + ips[1],
												     "CleanMx(virus)")));
				}
				
				/* address -> DNSName */
				if (addressObservable != null && dnsObservable != null)	{
					addressObservable
						.getObject()
							.withRelatedObjects(new RelatedObjectsType()
								.withRelatedObjects(setRelatedObject(dnsObservable.getId(), 
											     "address has DNSName",
											     ip + ", port 80 has DNS name " + dns,
											     "CleanMx(virus)"))); 
				}				
				
				/* malware -> address relation */
				if (malwareIndicator != null && addressObservable != null) {
					malwareIndicator
						.withObservable(new Observable()
							.withIdref(addressObservable.getId()));
				} 
				
				if (addressObservable != null) {
					observables
						.withObservables(addressObservable);
				}

				if (ipObservable != null) {
					observables
						.withObservables(ipObservable);
				}
				if (malwareIndicator != null) {
					indicators
						.withIndicators(malwareIndicator);
				}
			}

			if (!indicators.getIndicators().isEmpty()) {
				stixPackage
					.withIndicators(indicators);
			}
			if (!observables.getObservables().isEmpty()) {
				stixPackage
					.withObservables(observables);
			}

			return stixPackage;				

		} catch (DatatypeConfigurationException e) {
			e.printStackTrace();
		}

		return null;
	}
}
