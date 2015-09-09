package STIXExtractor;

import java.util.Set;
import java.util.HashSet;
import java.util.List;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Map;
import java.util.HashMap;
import java.util.UUID;

import java.io.IOException;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.namespace.QName;

import org.apache.commons.net.util.SubnetUtils;
import org.apache.commons.net.util.SubnetUtils.SubnetInfo;

import org.mitre.stix.stix_1.STIXPackage;
import org.mitre.cybox.cybox_2.Observables;
import org.mitre.cybox.cybox_2.Observable;
import org.mitre.cybox.cybox_2.ObjectType;
import org.mitre.cybox.cybox_2.Observable;
import org.mitre.cybox.cybox_2.Observables;
import org.mitre.cybox.cybox_2.ObservableCompositionType;
import org.mitre.cybox.cybox_2.OperatorTypeEnum;
import org.mitre.cybox.cybox_2.RelatedObjectsType;
import org.mitre.cybox.cybox_2.RelatedObjectType;
import org.mitre.cybox.common_2.StringObjectPropertyType;
import org.mitre.cybox.common_2.StructuredTextType;
import org.mitre.cybox.common_2.RegionalRegistryType;
import org.mitre.cybox.objects.WhoisEntry;
import org.mitre.cybox.objects.WhoisContactType;
import org.mitre.cybox.objects.Address;
import org.mitre.cybox.objects.WhoisRegistrantsType;
import org.mitre.cybox.objects.WhoisRegistrantInfoType;

/**
 * Caida data to STIX format extractor
 *
 * Maps organization to ASNs and ASN to prefixes
 * Returns null if document is empty or doesn't contain ASNs matching with organizations or prefixes
 * 
 * @author Maria Vincent
 */
public class CaidaExtractor extends STIXExtractor {
						
	private static final Logger logger = LoggerFactory.getLogger(CaidaExtractor.class);
	private static Set<String> rirSet = new HashSet<String>(Arrays.asList("AFRINIC", "ARIN", "APNIC", "LACNIC", "RIPE"));
	private STIXPackage stixPackage;

	public CaidaExtractor(String as2orgInfo, String pfx2asInfo) {
		stixPackage = extract(as2orgInfo, pfx2asInfo);
	}

	public STIXPackage getStixPackage() {
		return stixPackage;
	}

	private STIXPackage extract (String as2orgInfo, String pfx2asInfo) {
		try {
			Observables observables = initObservables();
			InputStream is = new ByteArrayInputStream(as2orgInfo.getBytes());
			BufferedReader br = new BufferedReader(new InputStreamReader(is));
			String line;

			Map<String, String[]> orgMap = new HashMap<String, String[]>();		
			Map<String, List<String[]>> asnMap = new HashMap<String, List<String[]>>();
			Set<String> asnSet = new HashSet<String>();
			boolean marked = false;
			while ((line = br.readLine()) != null) {

				/* organization map */
				if (line != null && line.equals("# format:org_id|changed|org_name|country|source")) {
					if (marked) {
						br.reset();
					}
					while ((line = br.readLine()) != null) {
						if (line.startsWith("# format")) {
							br.mark(0);
							marked = true;
							break;
						}
						String[] orgInfoArray = line.split("\\|");
						orgMap.put(orgInfoArray[0], orgInfoArray);
					}
				}

				/* asn map */
				if (line != null && line.equals("# format:aut|changed|aut_name|org_id|source")) {
					if (marked) {
						br.reset();
					}
					while ((line = br.readLine()) != null) {
						if (line.startsWith("# format")) {
							br.mark(0);
							marked = true;
							break;
						}
						String[] as2org = line.split("\\|");
						List<String[]> prefixList = (asnMap.containsKey(as2org[3])) ? asnMap.get(as2org[3]) : new ArrayList<String[]>();
						prefixList.add(as2org);
						asnMap.put(as2org[3], prefixList);
						asnSet.add(as2org[0]);
					}
				}
			}

			/* prefix map */
			Map<String, List<String>> prefixMap = new HashMap<String, List<String>>();
			is = new ByteArrayInputStream(pfx2asInfo.getBytes());
			br = new BufferedReader(new InputStreamReader(is));
			while ((line = br.readLine()) != null) {
				String[] prefixArray = line.split("\\t| ");
				if (prefixArray[2].contains(",") || prefixArray[2].contains("_")) {
					String[] asnNumbers = prefixArray[2].split(",|_");
					for (int i = 0; i < asnNumbers.length; i++) {
						if (asnSet.contains(asnNumbers[i])) {
							List<String> prefixList = (prefixMap.containsKey(asnNumbers[i])) ? prefixMap.get(asnNumbers[i]) : new ArrayList<String>();
							prefixList.add(prefixArray[0] + "/" + prefixArray[1]);								
							prefixMap.put(asnNumbers[i], prefixList);
						}	
					}
				} else {
					if (asnSet.contains(prefixArray[2])) {
						List<String> prefixList = (prefixMap.containsKey(prefixArray[2])) ? prefixMap.get(prefixArray[2]) : new ArrayList<String>();
						prefixList.add(prefixArray[0] + "/" + prefixArray[1]);								
						prefixMap.put(prefixArray[2], prefixList);
					}	
				}		
			}
	
			List<QName> asnId = new ArrayList<QName>();
			for (String asnKey : asnMap.keySet()) {
				List<QName> asnIdList = new ArrayList<QName>();
				List<String[]> asnList = asnMap.get(asnKey);
				
				/* asn observable (adding only if it has matching organization or prefix) */
				for (String[] asn : asnList) {
					Observable asnObservable = setASNObservable(asn[0], asn[2], asn[4], "Caida");
					asnIdList.add(asnObservable.getId());
			
					if (prefixMap.containsKey(asn[0])) {
						List<String> prefixList = prefixMap.get(asn[0]);
						List<RelatedObjectType> relatedObjects = new ArrayList<RelatedObjectType>();

						/* addressRange observable */
						for (String prefix : prefixList) {
							SubnetUtils utils = new SubnetUtils(prefix);
							SubnetInfo info = utils.getInfo();
							utils.setInclusiveHostCount(true);	//range includes network address and broadcast address?? 
							Observable addressRangeObservable = setAddressRangeObservable(info.getLowAddress(), info.getHighAddress(), "Caida");
							observables
								.withObservables(addressRangeObservable);	
							relatedObjects.add(setRelatedObject(addressRangeObservable.getId(), "hostsAddressRange", 
								"AS " + asn[2] + " with ASN " + asn[0] + "  hosts IP address range " + info.getLowAddress() + " through " + info.getHighAddress(), 
									"Caida"));
						}

						/* asn -> addressRange */
						if (!relatedObjects.isEmpty()) {
							asnObservable
								.getObject()
									.withRelatedObjects(new RelatedObjectsType()
										.withRelatedObjects(relatedObjects));
						}
						observables
							.withObservables(asnObservable);
						asnId.add(asnObservable.getId());
					} else {
						if (orgMap.containsKey(asnKey)) {
							observables
								.withObservables(asnObservable);
							asnId.add(asnObservable.getId());
						}
					}
				}
				if (orgMap.containsKey(asnKey) && !asnIdList.isEmpty()) {

					// if given asn contains multiple prefixes, then creating observable composition
					Observable asnObservable = null;
					if (asnIdList.size() > 1) {
						ObservableCompositionType composition = new ObservableCompositionType()
							.withOperator(OperatorTypeEnum.AND);
						for (QName id : asnIdList) {
							composition
								.withObservables(new Observable()
									.withIdref(id));
						}
						asnObservable = new Observable()
							.withObservableComposition(composition);
					}


					/* organization Observable */
					String[] orgInfo = orgMap.get(asnKey);
					Observable organizationObservable = new Observable()
						.withId(new QName("gov.ornl.stucco", "organization-" + UUID.randomUUID().toString(), "stucco"))
	           				.withTitle("Organization")
               					.withObservableSources(setMeasureSourceType("Caida"))
                    				.withObject(new ObjectType()
                   					.withId(new QName("gov.ornl.stucco", "organization-" + makeId(orgInfo[2]), "stucco"))
	                               		.withDescription(new StructuredTextType()
        	             				.withValue("Organization " + orgInfo[2] + " located in " + orgInfo[3] + " has a range of IP addresses"))
                	        		.withProperties(new WhoisEntry()
							.withIPAddress(new Address()	
								.withObjectReference((asnObservable == null) ? asnIdList.get(0) : asnObservable.getId()))
							.withRegistrants(new WhoisRegistrantsType()
								.withRegistrants(new WhoisRegistrantInfoType()
									.withRegistrantID(new StringObjectPropertyType()
										.withValue(orgInfo[0]))
									.withOrganization((orgInfo[2].isEmpty()) ? null : new StringObjectPropertyType()
										.withValue(orgInfo[2]))
									.withAddress((orgInfo[3].isEmpty()) ? null : new StringObjectPropertyType()
										.withValue(orgInfo[3]))))));
					observables
						.withObservables(organizationObservable);
				}
			}
			

			return (observables.getObservables().isEmpty()) ? null :  initStixPackage("Caida").withObservables(observables);

		} catch (DatatypeConfigurationException e) {
			e.printStackTrace();
		} catch (IOException e)	{
			e.printStackTrace();
		}

		return null;
	}
}
