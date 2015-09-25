package STIXExtractor;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.namespace.QName;					

import org.mitre.stix.stix_1.STIXPackage;
import org.mitre.stix.common_1.ExploitTargetsType;
import org.mitre.stix.common_1.StructuredTextType;
import org.mitre.stix.common_1.ReferencesType;
import org.mitre.stix.exploittarget_1.ExploitTarget;
import org.mitre.stix.exploittarget_1.VulnerabilityType;

public class CveExtractor extends STIXExtractor {
						
	private static final Logger logger = LoggerFactory.getLogger(CveExtractor.class);
	private STIXPackage stixPackage;

	public CveExtractor(String cveInfo) {
		stixPackage = extract(cveInfo);
	}
					
	public STIXPackage getStixPackage() {
		return stixPackage;
	}

	private STIXPackage extract (String cveInfo) {
		try {
			Document doc = Jsoup.parse(cveInfo);
			Elements entries = doc.select("item");
			
			if (entries.isEmpty()) {
				return null;
			}

			stixPackage = initStixPackage("CVE");				
			ExploitTargetsType exploitTargets = new ExploitTargetsType();			

			for (Element entry : entries) {	
				VulnerabilityType vulnerability = new VulnerabilityType();
				ReferencesType referencesType = new ReferencesType();

				vulnerability
					.withCVEID((!entry.hasAttr("name")) ? null : entry.attr("name"))
					.withIsPubliclyAcknowledged((entry.select("status").text().equals("Candidate")) 
						? false : ((entry.select("status").text().equals("Entry")) ? true : null));
				
				if (entry.select("desc").hasText()) {
					vulnerability
						.withDescriptions((!entry.select("desc").hasText()) ? null : new StructuredTextType()
							.withValue(entry.select("desc").text()));
				}
										
				//references
				Elements references = entry.select("ref");
				if (!references.isEmpty()) {
					for (Element reference : references) {
						referencesType
							.withReferences((reference.hasAttr("url")) 
								? reference.attr("url") : reference.attr("source") + ":" + reference.text());
					}
	
					vulnerability
						.withReferences(referencesType);
				}

				//comments
				Elements comments = entry.select("comment");			
				for (Element comment : comments) {
					vulnerability
						.withShortDescriptions(new StructuredTextType()		
							.withValue(comment.select("comment").text()));
				}
		
				exploitTargets
					.withExploitTargets(new ExploitTarget()
						.withId(new QName("gov.ornl.stucco", "cveId_" + entry.attr("name"), "stucco"))
						.withTitle("Vulnerability")
						.withVulnerabilities(vulnerability	
							.withSource("CVE")));	
			}				
			
			return stixPackage
				.withExploitTargets(exploitTargets);
			
		} catch (DatatypeConfigurationException e) {
			e.printStackTrace();
		} 

		return null;
	}
}
