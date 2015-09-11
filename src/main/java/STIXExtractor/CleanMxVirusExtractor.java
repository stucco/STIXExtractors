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
public class CleanMxVirusExtractor extends STIXExtractor {
							
	private static final Logger logger = LoggerFactory.getLogger(CleanMxVirusExtractor.class);

	private STIXPackage stixPackage;
										
	public CleanMxVirusExtractor(String cleanMxInfo) {
		stixPackage = extract(cleanMxInfo);
	}
					
	public STIXPackage getStixPackage() {
		return stixPackage;
	}

	private STIXPackage extract (String cleanMxInfo) {
		try {
			Document doc = Jsoup.parse(cleanMxInfo);
			Elements entries = doc.select("entry");
			
			if (entries.isEmpty()) {
				return null;
			}
			
			Observables observables = initObservables();
			IndicatorsType indicators = new IndicatorsType();

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
					
					malwareIndicator = new Indicator()
						.withId(new QName("gov.ornl.stucco", "malware-" + UUID.randomUUID().toString(), "stucco"))
						.withTitle("Malware")
						.withIndicatedTTPs(new RelatedTTPType()
							.withTTP(initTTP("Malware", "CleanMx(virus)")
								.withBehavior(new BehaviorType()
									.withMalware(new MalwareType()
										.withMalwareInstances(setMalwareInstance(entry.select("id").text(), "CleanMx(virus)")
											.withNames((!entry.select("virusname").hasText()) ? null : new ControlledVocabularyStringType()
												.withValue(entry.select("virusname").text())))))
								.withResources((!entry.select("md5").hasText()) ? null : new ResourceType()
									.withTools(new ToolsType()
										.withTools(new ToolInformationType()	//list
											.withToolHashes(new HashListType()
												.withHashes(setHashType(entry.select("md5").text(), "md5"))))))));
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

					ns												
						.withNameservers((!entry.select("ns1").hasText()) ? null : setURIObjectType(entry.select("ns1").text()))
						.withNameservers((!entry.select("ns2").hasText()) ? null : setURIObjectType(entry.select("ns2").text()))
						.withNameservers((!entry.select("ns3").hasText()) ? null : setURIObjectType(entry.select("ns3").text()))
						.withNameservers((!entry.select("ns4").hasText()) ? null : setURIObjectType(entry.select("ns4").text()))
						.withNameservers((!entry.select("ns5").hasText()) ? null : setURIObjectType(entry.select("ns5").text()));
					
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
								.withRelatedObjects(setRelatedObject(addressRangeObservable.getId(), "inAddressRange",
									ip + " is in address range " + ips[0] + " through " + ips[1], "CleanMx(virus)")));
				}
				
				/* address -> DNSName */
				if (addressObservable != null && dnsObservable != null)	{
					addressObservable
						.getObject()
							.withRelatedObjects(new RelatedObjectsType()
								.withRelatedObjects(setRelatedObject(dnsObservable.getId(), "hasDNSName",
									ip + ", port 80 has DNS name " + dns, "CleanMx(virus)"))); 
				}				
				
				/* malware -> address relation */
				if (malwareIndicator != null && addressObservable != null) {
					malwareIndicator
						.withObservable(new Observable()
							.withIdref(addressObservable.getId()));
				} 
				
				observables
					.withObservables((addressObservable == null) ? null : addressObservable)
					.withObservables((ipObservable == null) ? null : ipObservable);
				
				indicators
					.withIndicators((malwareIndicator == null) ? null : malwareIndicator);

			}

			return (indicators.getIndicators().isEmpty() && observables.getObservables().isEmpty()) ? null : initStixPackage("CleanMx(virus)")				
					.withIndicators((indicators.getIndicators().isEmpty()) ? null : indicators)
					.withObservables((observables.getObservables().isEmpty()) ? null : observables);

		} catch (DatatypeConfigurationException e) {
			e.printStackTrace();
		}

		return null;
	}
}