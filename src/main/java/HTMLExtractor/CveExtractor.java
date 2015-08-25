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

import org.xml.sax.SAXException;			

public class CveExtractor extends HTMLExtractor {
						
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
				String cveId = "cve-";
				ExploitTarget exploitTarget = new ExploitTarget();
				VulnerabilityType vulnerability = new VulnerabilityType();
				ReferencesType referencesType = new ReferencesType();

				//cve		
				if (entry.hasAttr("name"))	{
					vulnerability
						.withCVEID(entry.attr("name"));
					cveId = "cve-" + entry.attr("name");
				}

				//description
				if (entry.select("desc").hasText()) {
					vulnerability
						.withDescriptions(new StructuredTextType()
							.withValue(entry.select("desc").text()));
				}
				
				//status 
				if (entry.select("status").text().equals("Candidate")) {
					vulnerability
						.withIsPubliclyAcknowledged(false);
				}
				
				if (entry.select("status").text().equals("Entry")) {
					vulnerability
						.withIsPubliclyAcknowledged(true);
				}
										
				//references
				Elements references = entry.select("ref");
				if (!references.isEmpty()) {
					for (Element reference : references) {
						if (reference.hasAttr("url")) {
							referencesType
								.withReferences(reference.attr("url"));
						} else {
							referencesType
								.withReferences(reference.attr("source") + ":" + reference.text());
						}
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
					.withExploitTargets(exploitTarget		
						.withId(new QName("gov.ornl.stucco", cveId, "stucco"))
						.withTitle("CVE")
						.withVulnerabilities(vulnerability	
							.withSource("CVE")));	
			}				
			
			return stixPackage
				.withExploitTargets(exploitTargets);
			
		} catch (DatatypeConfigurationException e)	{
			e.printStackTrace();
		} 

		return null;
	}
}
