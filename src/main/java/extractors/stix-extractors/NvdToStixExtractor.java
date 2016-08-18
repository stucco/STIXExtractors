package STIXExtractor;

import java.util.GregorianCalendar;
import java.util.UUID;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.xml.datatype.DatatypeFactory;
import javax.xml.namespace.QName;				
import javax.xml.datatype.DatatypeConfigurationException;

import org.mitre.stix.stix_1.STIXPackage;
import org.mitre.stix.common_1.ExploitTargetsType;
import org.mitre.stix.common_1.StructuredTextType;
import org.mitre.stix.common_1.DateTimeWithPrecisionType;
import org.mitre.stix.common_1.ReferencesType;
import org.mitre.stix.common_1.RelatedObservableType;
import org.mitre.stix.exploittarget_1.VulnerabilityType;
import org.mitre.stix.exploittarget_1.CVSSVectorType;
import org.mitre.stix.exploittarget_1.AffectedSoftwareType;
import org.mitre.stix.exploittarget_1.ExploitTarget;
import org.mitre.cybox.cybox_2.Observables;
import org.mitre.cybox.cybox_2.Observable;

/**
 * NVD to STIX extractor
 *
 * @author Maria Vincent
 */
public class NvdToStixExtractor extends STIXUtils {
							
	private static final Logger logger = LoggerFactory.getLogger(NvdToStixExtractor.class);
	
	private STIXPackage stixPackage;
										
	//empty constractor for test purpose
	public NvdToStixExtractor(){};

	public NvdToStixExtractor(String nvdInfo) {
		stixPackage = extract(nvdInfo);
	}
					
	public STIXPackage getStixPackage() {
		return stixPackage;
	}
	
	private long convertTimestamp(String time) { 
		if (time.endsWith("Z")) {
			return convertTimestamp(time.replaceAll("Z$", "+0000"), "yyyy-MM-dd'T'HH:mm:ss.SSSZ");
		} else {
			return convertTimestamp(time, "yyyy-MM-dd'T'HH:mm:ss.SSSXXX");
		}
	}

	private STIXPackage extract (String nvdInfo) {
		Document doc = Jsoup.parse(nvdInfo);
		Elements entries = doc.select("entry[id~=CVE-\\d{4}-\\d{4,7}]");

		if (entries.isEmpty()) {
			return null;
		}

		Observables observables = initObservables();
		ExploitTargetsType ets = new ExploitTargetsType();
		GregorianCalendar calendar = new GregorianCalendar();
		
		for (Element entry : entries) {

			VulnerabilityType vulnerability = new VulnerabilityType();

			/* vulnerability */

			//description
			if (!entry.select("vuln|summary").isEmpty()) {
				vulnerability
					.withDescriptions(new StructuredTextType()             
							.withValue(entry.select("vuln|summary").text()));				
			}

			//cve 
			if (!entry.select("vuln|cve-id").isEmpty()) {
				vulnerability
						.withCVEID(entry.select("vuln|cve-id").text());
			} else	{
				vulnerability
						.withCVEID(entry.select("entry").attr("id"));
			}

			//CVSS Score
			if (!entry.select(" > vuln|cvss > cvss|base_metrics > cvss|score").isEmpty()) {
				vulnerability
						.withCVSSScore(new CVSSVectorType()
						.withBaseScore(entry.select(" > vuln|cvss > cvss|base_metrics > cvss|score").text()));
			}

			//publishedDate
			if (!entry.select("vuln|published-datetime").isEmpty())	{
				calendar.setTimeInMillis(convertTimestamp(entry.select("vuln|published-datetime").text()));	
				try {
					vulnerability
						.withPublishedDateTime(new DateTimeWithPrecisionType()
						.withValue(DatatypeFactory.newInstance().newXMLGregorianCalendar(calendar)));
				} catch (DatatypeConfigurationException e) {
					e.printStackTrace();
				}
			}

			//references
			Elements references = entry.select("vuln|references");
			if (!references.isEmpty()) {
			
				ReferencesType referencesType = new ReferencesType();
			
				for (Element reference : references) {
					String refContent = (reference.select("vuln|reference").first().attr("href").isEmpty())
                                        		? reference.select("vuln|source").text() + ":" + reference.select("vuln|reference").text()
                                        		: reference.select("vuln|reference").first().attr("href");

					referencesType
						.withReferences(refContent);
				}

				vulnerability
					.withReferences(referencesType);
			}

			/* software */
			AffectedSoftwareType affectedSoftware = new AffectedSoftwareType();
			Elements vulnerableSoftware = entry.select("vuln|vulnerable-software-list > vuln|product");

			for (Element software : vulnerableSoftware) {
				Observable softwareObservable = setSoftwareObservable(software.text(), makeSoftwareDesc(software.text()), "NVD");	
				observables
					.withObservables(softwareObservable);	
				affectedSoftware	
					.withAffectedSoftwares(new RelatedObservableType()
                     					.withObservable(new Observable()
							.withIdref(softwareObservable.getId())));
			}
		
			/* vulnerability -> software */
			if (!affectedSoftware.getAffectedSoftwares().isEmpty()) {				
				vulnerability
					.withAffectedSoftware(affectedSoftware);
			
			}

			ets
				.withExploitTargets(new ExploitTarget()
					.withId(new QName("gov.ornl.stucco", "vulnerability-" + UUID.randomUUID().toString(), "stucco"))
					.withTitle("Vulnerability")
					.withVulnerabilities(vulnerability
							.withSource("NVD")));
		} 

		if (!observables.getObservables().isEmpty()) {
			try {
				stixPackage = initStixPackage("Vulnerability Description", "NVD")
					.withObservables(observables);
			} catch (DatatypeConfigurationException e)	{
				e.printStackTrace();
				return null;
			}	
		}
		if (!ets.getExploitTargets().isEmpty()) {
			if (stixPackage == null) {
				try {
					stixPackage = initStixPackage("Vulnerability Description", "NVD")
						.withExploitTargets(ets);
				} catch (DatatypeConfigurationException e)	{
					e.printStackTrace();
					return null;
				}	
			} else {
				stixPackage
					.withExploitTargets(ets);
			}
		}

		return stixPackage;
	}
}
