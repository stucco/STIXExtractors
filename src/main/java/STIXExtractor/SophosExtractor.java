package STIXExtractor;

import java.util.Set;
import java.util.List;
import java.util.ArrayList;
import java.util.TreeSet;
import java.util.Map;
import java.util.LinkedHashSet;
import java.util.Iterator;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.nodes.Node;
import org.jsoup.select.Elements;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.mitre.stix.stix_1.STIXPackage;
import org.mitre.stix.stix_1.TTPsType;
import org.mitre.stix.stix_1.IndicatorsType;
import org.mitre.stix.indicator_2.Indicator;
import org.mitre.stix.ttp_1.MalwareInstanceType;
import org.mitre.stix.ttp_1.MalwareType;
import org.mitre.stix.ttp_1.BehaviorType;
import org.mitre.stix.ttp_1.TTP;
import org.mitre.stix.ttp_1.VictimTargetingType;
import org.mitre.stix.ttp_1.ToolsType;
import org.mitre.stix.ttp_1.ResourceType;
import org.mitre.stix.ttp_1.InfrastructureType;
import org.mitre.stix.common_1.ControlledVocabularyStringType;
import org.mitre.stix.common_1.StructuredTextType;
import org.mitre.stix.common_1.InformationSourceType;
import org.mitre.stix.common_1.RelatedTTPType;
import org.mitre.stix.common_1.ToolInformationType;
import org.mitre.cybox.cybox_2.AssociatedObjectType;
import org.mitre.cybox.cybox_2.AssociatedObjectsType;
import org.mitre.cybox.cybox_2.Observable;
import org.mitre.cybox.cybox_2.Observables;
import org.mitre.cybox.cybox_2.ObjectType;
import org.mitre.cybox.cybox_2.ActionsType;
import org.mitre.cybox.cybox_2.ActionPoolType;
import org.mitre.cybox.cybox_2.Event;
import org.mitre.cybox.cybox_2.RelatedObjectsType;
import org.mitre.cybox.cybox_2.OperatorTypeEnum;
import org.mitre.cybox.cybox_2.ObservableCompositionType;	
import org.mitre.cybox.cybox_2.PoolsType;
import org.mitre.cybox.cybox_2.ActionsType;
import org.mitre.cybox.common_2.DatatypeEnum;
import org.mitre.cybox.common_2.Property;
import org.mitre.cybox.common_2.HashType;
import org.mitre.cybox.common_2.CustomPropertiesType;
import org.mitre.cybox.common_2.StringObjectPropertyType;
import org.mitre.cybox.common_2.HashListType;
import org.mitre.cybox.common_2.SimpleHashValueType;
import org.mitre.cybox.objects.ProcessObjectType;
import org.mitre.cybox.objects.WindowsRegistryKey;
import org.mitre.cybox.objects.FileObjectType;
import org.mitre.maec.xmlschema.maec_bundle_4.MalwareActionType;

import java.util.GregorianCalendar;
import javax.xml.datatype.DatatypeConfigurationException;

public class SophosExtractor extends STIXExtractor {
	
	private static final Logger logger = LoggerFactory.getLogger(SophosExtractor.class);
	
	private STIXPackage stixPackage;

	public SophosExtractor(String summary, String details) {
		stixPackage = extract(summary, details);
	}
	
	public STIXPackage getStixPackage() {
		return stixPackage;
	}
	
	private long convertTimestamp(String time) { 
		return convertTimestamp(time, "dd MMM yyyy hh:mm:ss");
	}
	
	private long convertShortTimestamp(String time)	{ 
		return convertTimestamp(time + " (GMT)", "yyyy-MM-dd (z)");
	}
	
	private STIXPackage extract(String summary, String details) {
			TTP ttp = initTTP("Malware", "Sophos");				
			MalwareInstanceType malware = new MalwareInstanceType();
			Observables observables = initObservables();
			Observables infrastructureObservables = initObservables();
			ResourceType resource = null;
			ToolsType tools = new ToolsType();
			try {
				stixPackage = initStixPackage("Malware Description", "Sophos");				
			} catch(DatatypeConfigurationException e) {
				e.printStackTrace();
				return null;
			} 			
			TreeSet<String> aliasSet = new TreeSet<String>();
			
			//TODO there is not stix field for thore properties .... leave them out for now
			Property discoveredDateTime = setCustomProperty("DiscoveredDate", "0")
				.withDatatype(DatatypeEnum.UNSIGNED_LONG);
			Property modifiedDateTime = setCustomProperty("ModifiedDate", "0")
				.withDatatype(DatatypeEnum.UNSIGNED_LONG);
			Property prevalence = setCustomProperty("Prevalence", null)
				.withDatatype(DatatypeEnum.STRING);
			long signatureDate = 0L; 		
			long discoveredDate = 0L;

			//process the "summary" page
 			Document doc = Jsoup.parse(summary);
			Element content = doc.getElementsByClass("tertiaryBump").first();
			logger.debug(content.html());
		
			//get the title, set up name & other known fields
			Element titleDiv = content.getElementsByClass("marqTitle").first();
			logger.debug(titleDiv.html());
			String vertexName = titleDiv.getElementsByTag("h1").first().text();
			logger.info("Name: {}", vertexName);
			if (!vertexName.isEmpty()) {
				malware
					.withTitle(vertexName);
				malware
					.withDescriptions(new StructuredTextType()
						.withValue(vertexName));
			}

			//name
			aliasSet.add(vertexName);		

			//TODO add signature and discovered dates
			Element rowOne = titleDiv.getElementsByTag("tr").first();
			String addedDate = rowOne.child(3).text();
			if(!addedDate.equals("")) {
				//some don't list dates, not sure why
			//	signatureDate = convertTimestamp(addedDate);
				discoveredDate = convertTimestamp(addedDate);
			}			
		
			//type
			Element rowTwo = titleDiv.getElementsByTag("tr").get(1);
			String type = rowTwo.child(1).text();
			if (!type.isEmpty()) {
				malware
					.withTypes(new ControlledVocabularyStringType()
						.withValue(type));
			}
	
			//TODO add modified date																
			String modifiedDate = rowTwo.child(3).text();
			if(!modifiedDate.equals(""))	{
				modifiedDateTime 
					.setValue(Long.toString(convertTimestamp(addedDate)));	//modifiedDAte
			}

			//prevalence											
			Element rowThree = titleDiv.getElementsByTag("tr").get(2);
			String prev = rowThree.child(1).getElementsByTag("img").first().attr("alt");
			logger.info("Prevalence: {}", prev);
			if (!prev.isEmpty()) {
				prevalence 
					.withValue(prev);
			}

			//alias
			Element secondaryDiv = doc.getElementsByClass("secondaryContent").first();
			logger.debug(secondaryDiv.html());
			Elements aliasItems = secondaryDiv.getElementsByClass("aliases");
			if (!aliasItems.isEmpty()) { 
				aliasItems = aliasItems.first().children();
				logger.debug(aliasItems.outerHtml());
				for(int i=0; i<aliasItems.size(); i++) {
					aliasSet.add(aliasItems.get(i).text());
				}
				aliasSet.add(vertexName);
			}

			//platform
			Elements h3s = secondaryDiv.getElementsByTag("h3");
			Element affectedHeading = null;
			for (int i=0; i<h3s.size(); i++) {
				if (h3s.get(i).text().equals("Affected Operating Systems")) {
					affectedHeading = h3s.get(i);
					break;
				}
			}
			if (affectedHeading != null) {
				Element nextSibling = affectedHeading.nextElementSibling();
				if (nextSibling != null) {
					Elements platformElements = nextSibling.getElementsByTag("img");
					if (!platformElements.isEmpty()) {
					//	System.out.println(platformNames.isEmpty());
					//	.first().attr("alt1");
						Element platformElement = platformElements.first();
						if (platformElement.hasAttr("alt")) {
							String platformName = platformElement.attr("alt");
							ttp
								.withVictimTargeting(new VictimTargetingType()
									.withTargetedSystems(new ControlledVocabularyStringType()
										.withValue(platformName)));
							logger.info("Platform: {}", platformName);
						}
					}
				}
			}
		
			doc = Jsoup.parse(details);
			content = doc.getElementsByClass("threatDetail").first();
			Elements h4headings = content.getElementsByTag("h4");
			Element curr, nextSibling;
			Map<String,String> currTableContents;
			long firstSeen;
			boolean runtimeAnalysisFound = false;

			for (int i=0; i<h4headings.size(); i++) {
				curr = h4headings.get(i);
				nextSibling = curr.nextElementSibling();
				if (curr.text().equals("File Information") && nextSibling.tagName().equals("dl")) {
					logger.debug("Found a file info table: \n{}", nextSibling.html());
					currTableContents = dlToMap(nextSibling);  
					if (currTableContents == null) {
						logger.error("Could not parse table contents! (file info)");
					} else {			
						ToolInformationType fileTool = null;
						List<HashType> hashes = new ArrayList<HashType>();
						firstSeen = 0;

						logger.info("Extracted map from file info table: {}", currTableContents);
						if (currTableContents.containsKey("SHA-1")) {
							hashes.add(setHash("SHA-1", currTableContents.get("SHA-1")));
						}
						if (currTableContents.containsKey("MD5")) {
							hashes.add(setHash("MD5", currTableContents.get("MD5")));
						}					
						if (currTableContents.containsKey("File type")) {
							fileTool = new ToolInformationType()
								.withName(currTableContents.get("File type"))
								.withTypes(new org.mitre.cybox.common_2.ControlledVocabularyStringType()
									.withValue("File"));
						}
						if (currTableContents.containsKey("First seen")) { 
							firstSeen = convertShortTimestamp(currTableContents.get("First seen"));
							//have to do all those comvertions, or toXMLString() would not work ....	
							if (firstSeen < Long.parseLong(discoveredDateTime.getValue().toString())) {
								discoveredDate = firstSeen;
							}
						}	
						if (!hashes.isEmpty()) {
							if (fileTool == null) {	
								fileTool = new ToolInformationType();
							}
							fileTool
								.withToolHashes(new HashListType()
										.withHashes(hashes));
						}
						if (fileTool != null) {
							tools
								.withTools(fileTool);
						}
					}
				} else if (curr.text().equals("Runtime Analysis")) {
					//could do this here, but it's kind of complicated, better to separate it out...
					runtimeAnalysisFound = true;
					logger.info("Runtime Analysis section found, handling later...");
				} else if (curr.text().equals("Other vendor detection") && nextSibling.tagName().equals("dl")) {
					currTableContents = dlToMap(nextSibling); 
					if (currTableContents == null) {
						logger.error("Could not parse table contents! (other vendor detection)");
					} else { 
						logger.info("Extracted map from 'other vendor detection table: {}", currTableContents);
						Set<String> keys = currTableContents.keySet();
						Iterator<String> keysIter = keys.iterator();
						while (keysIter.hasNext()) {
							aliasSet.add(currTableContents.get(keysIter.next()));
						}
						logger.info("  now know aliases: {}", aliasSet);
					}
				} else {
					logger.warn("Unexpected H4 Found: {}", curr.text());
				}
			}

			//alias
			for (String alias : aliasSet) {
				malware
					.withNames(new ControlledVocabularyStringType()
						.withValue(alias));
			}
			
			//handle the "Runtime Analysis" sections...
			if (runtimeAnalysisFound) {
				Element nextNextSibling;
				Set<String> ipConnections = new LinkedHashSet<String>();
				Set<String> dnsRequests = new LinkedHashSet<String>();

				Set<AssociatedObjectType> createdFiles = new LinkedHashSet<AssociatedObjectType>();;
				Set<AssociatedObjectType> modifiedFiles = new LinkedHashSet<AssociatedObjectType>();
				Set<AssociatedObjectType> createdProcesses = new LinkedHashSet<AssociatedObjectType>();
				Set<AssociatedObjectType> createdRegistryKeys = new LinkedHashSet<AssociatedObjectType>();
				Set<AssociatedObjectType> modifiedRegistryKeys = new LinkedHashSet<AssociatedObjectType>();

				for (int i=0; i<h4headings.size(); i++) {
					curr = h4headings.get(i);
					nextSibling = curr.nextElementSibling();
					nextNextSibling = nextSibling.nextElementSibling();
					Set<String> newItems;
					if (curr.text().equals("Runtime Analysis")) {
						logger.info("'Runtime Analysis' section found");
						while (nextSibling != null && nextSibling.tagName().equals("h5") && 
								nextNextSibling != null && nextNextSibling.tagName().equals("ul")) {
							if (nextSibling.text().equals("Dropped Files")) {
								//TODO save other fields?  MD5 & etc?
								newItems = ulToSet(removeGrandchildren(nextNextSibling));
								createdFiles.addAll(setFiles(newItems));
								logger.info("Dropped Files: {}", newItems);
							}
							else if (nextSibling.text().equals("Copies Itself To")) {
								//TODO save other fields?  MD5 & etc?
								newItems = ulToSet(removeGrandchildren(nextNextSibling));
								createdFiles.addAll(setFiles(newItems));
								logger.info("Copies Itself To: {}", newItems);
							}
							else if (nextSibling.text().equals("Modified Files")) {
								newItems = ulToSet(removeGrandchildren(nextNextSibling));
								modifiedFiles.addAll(setFiles(newItems));
								logger.info("Modified Files: {}", newItems);
							}
							else if (nextSibling.text().equals("Registry Keys Created")) {
								//TODO save other fields?
								newItems = ulToSet(removeGrandchildren(nextNextSibling));
								createdRegistryKeys.addAll(setRegistryKeys(newItems));
								logger.info("Registry Keys Created: {}", newItems);
							}
							else if (nextSibling.text().equals("Registry Keys Modified")) {
								//TODO save other fields?
								newItems = ulToSet(removeGrandchildren(nextNextSibling));
								modifiedRegistryKeys.addAll(setRegistryKeys(newItems));
								logger.info("Registry Keys Modified: {}", newItems);
							}
							else if (nextSibling.text().equals("Processes Created")) {
								newItems = ulToSet(nextNextSibling);
								createdProcesses.addAll(setProcesses(newItems));
								logger.info("Processes Created: {}", newItems);
							}
							else if (nextSibling.text().equals("IP Connections")) {
								newItems = ulToSet(nextNextSibling);
								ipConnections.addAll(newItems);
								logger.info("IP Connections: {}", newItems);
							}
							else if (nextSibling.text().equals("DNS Requests")) {
								newItems = ulToSet(nextNextSibling);
								dnsRequests.addAll(newItems);
								logger.info("DNS Requests: {}", newItems);
							}
							else if (nextSibling.text().equals("HTTP Requests")) {
								newItems = ulToSet(nextNextSibling);
								tools
									.withTools(setTools("url", newItems).getTools());
								logger.info("HTTP Requests: {}", newItems);
							}
							else {
								logger.info("Unknown! {}:\n{}", nextSibling.text(), nextNextSibling.outerHtml());
							}
							nextSibling = nextNextSibling.nextElementSibling();
							if (nextSibling != null) {
								nextNextSibling = nextSibling.nextElementSibling();
							}
						}
					}
				}

				if (tools.getTools() != null) {
					resource = new ResourceType()
						.withTools(tools);
				}
				
				ActionsType actions = new ActionsType();
					
				if (!createdFiles.isEmpty()) {
					actions
						.withActions(setActions("Created", "Created files", createdFiles));
				}
				if (!modifiedFiles.isEmpty()) {
					actions
						.withActions(setActions("Modified", "Modified files", modifiedFiles));
				}
				if (!createdRegistryKeys.isEmpty()) {
					actions
						.withActions(setActions("Created", "Created registry keys", createdRegistryKeys));
				}
				if (!modifiedRegistryKeys.isEmpty()) {
					actions
						.withActions(setActions("Modified", "Modified registry keys", modifiedRegistryKeys));
				}
				if (!createdProcesses.isEmpty()) {
					actions
						.withActions(setActions("Created", "Created processes", createdProcesses));
				}

				if (!actions.getActions().isEmpty()) {
					infrastructureObservables
						.withObservables(new Observable()
							.withEvent(new Event()
								.withEvents(new Event()
									.withActions(actions))));
				}


				if (!ipConnections.isEmpty()) {
					Observable portObservable = null;								
					Observable ipObservable = null;								
					Observable addressObservable = null;	

					for (String ip : ipConnections) {
						String ipString;
						String portString;
						int port;
						try {
							port = getPortFromURL(ip);
						} catch (Exception e) {
							logger.warn("Exception when parsing port info from ip string " + ip, e);
							port = -1;
						}
						if (port != -1) {

							/* port */
							portString = Integer.toString(port);

							/* ip */
							portObservable = setPortObservable(portString, "Sophos");
							observables
								.withObservables(portObservable);
							ipString = (ip.endsWith(":" + portString)) ? ip.replace(":" + portString, "") : ip;
							ipObservable = setIpObservable(ipString, "Sophos");
							observables
								.withObservables(ipObservable);

							/* address */
							addressObservable = setAddressObservable(ipString, ipToLong(ipString), ipObservable.getId(), portString, portObservable.getId(), "Sophos");	
						} else { 
							//shouldn't ever give -1 anyway
							logger.warn("could not find port for ip string {}", ip);

							/* ip */
							ipObservable = setIpObservable(ip, "Sophos");
							observables
								.withObservables(ipObservable);

							/* address */
							addressObservable = setAddressObservable(ip, ipToLong(ip), ipObservable.getId(), "Sophos");	
						}
						observables
							.withObservables(addressObservable);
						infrastructureObservables
							.withObservables(new Observable()
								.withIdref(addressObservable.getId()));
					}
				}

				/* DNSName */
				if (!dnsRequests.isEmpty()) {
					Observable dnsObservable = null;
					Observable portObservable = null;
					Observable addressObservable = null;
					for (String dns : dnsRequests) {
						String dnsString = null;
						String portString = null;
						int port;
						try {
							port = getPortFromURL(dns);
						} catch (Exception e) {
							logger.warn("Exception when parsing port info from dns string " + dns, e);
							port = -1;
						}
						if (port != -1) {
							portString = Integer.toString(port);
							portObservable = setPortObservable(portString, "Sophos");
							observables
								.withObservables(portObservable);

							dnsString = (dns.endsWith(":" + portString)) ? dns.replace(":" + portString, "") : dns;
						} else { 
							//shouldn't ever give -1 anyway
							logger.warn("could not find port for dns string {}", dns);
							dnsString = dns;
						}

						dnsObservable = setDNSObservable(dnsString, "Sophos");
						observables
							.withObservables(dnsObservable);
						if (portObservable != null) {
							addressObservable = setDNSAddressObservable(portString, portObservable.getId(), dnsString, dnsObservable.getId(), "Sophos");
						} else {
							addressObservable = setDNSAddressObservable(dnsString, dnsObservable.getId(), "Sophos");
							addressObservable
								.getObject()
								.withRelatedObjects(new RelatedObjectsType()
										.withRelatedObjects(setRelatedObject(dnsObservable.getId(),
												"Has_DNSName",
												dnsString + ", port unknown has DNS name " + dnsString,
												"Sophos")));
						}
						observables
							.withObservables(addressObservable);
						infrastructureObservables
							.withObservables(new Observable()
								.withIdref(addressObservable.getId()));
					}

				}
			}

			if (!infrastructureObservables.getObservables().isEmpty()) {
				if (resource == null) {
					resource = new ResourceType();
				}
				resource
					.withInfrastructure(new InfrastructureType()
						.withObservableCharacterization(infrastructureObservables));
			}

			if (resource != null) {
				ttp
					.setResources(resource);
			} 
			
			if (!observables.getObservables().isEmpty()) {
				stixPackage
					.withObservables(observables);
			}

			stixPackage
				.withTTPs(new TTPsType()
					.withTTPS(ttp
						.withBehavior(new BehaviorType()
							.withMalware(new MalwareType()
								.withMalwareInstances(malware)))));

			return stixPackage;
		}
	}
