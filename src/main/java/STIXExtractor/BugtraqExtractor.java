package STIXExtractor;

import java.util.GregorianCalendar;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.UUID;

import java.math.BigInteger;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.namespace.QName;					

import org.mitre.stix.stix_1.STIXPackage;
import org.mitre.stix.stix_1.CoursesOfActionType;
import org.mitre.stix.common_1.RelatedCourseOfActionType;
import org.mitre.stix.common_1.StructuredTextType;
import org.mitre.stix.common_1.DateTimeWithPrecisionType;
import org.mitre.stix.common_1.RelatedObservableType;
import org.mitre.stix.common_1.ReferencesType;
import org.mitre.stix.common_1.ExploitTargetsType;
import org.mitre.stix.courseofaction_1.CourseOfAction;
import org.mitre.stix.exploittarget_1.ExploitTarget;
import org.mitre.stix.exploittarget_1.VulnerabilityType;
import org.mitre.stix.exploittarget_1.AffectedSoftwareType;
import org.mitre.stix.exploittarget_1.PotentialCOAsType;
import org.mitre.cybox.cybox_2.Observables;
import org.mitre.cybox.cybox_2.Observable;

public class BugtraqExtractor extends STIXExtractor {
							
	private static final Logger logger = LoggerFactory.getLogger(BugtraqExtractor.class);
	
	private STIXPackage stixPackage;
										
	public BugtraqExtractor(String info, String discussion, String exploit, String solution, String references) {
		stixPackage = extract(info, discussion, exploit, solution, references);
	}
					
	public STIXPackage getStixPackage() {
		return stixPackage;
	}
	
	private long convertTimestamp(String time) { 
		return convertTimestamp(time + " (GMT)", "MMM dd yyyy hh:mma");
	}
				
	private STIXPackage extract(String info, String discussion, String exploit, String solution, String references) {
		try {
			stixPackage = initStixPackage("Vulnerability Description", "Bugtraq");
			GregorianCalendar calendar = new GregorianCalendar();
			Observables observables = initObservables();
			ExploitTarget exploitTarget = new ExploitTarget();
			VulnerabilityType vulnerability = new VulnerabilityType();
			AffectedSoftwareType affectedSoftware = new AffectedSoftwareType();
					
			//process the "info" page
			Document doc = Jsoup.parse(info);
			Element content = doc.getElementById("vulnerability");
			
			//shortDescription
			if (!content.getElementsByClass("title").first().text().isEmpty()) {
	 			vulnerability
					.withShortDescriptions(new StructuredTextType()
						.withValue(content.getElementsByClass("title").first().text()));
			}

			//database id
			String regex = "(?s)\\s*?<td>.*?<span.*?>Bugtraq ID:</span>.*?</td>.*?<td>\\s*(.*?)\\s*</td>";
			String dbId = findWithRegex(content.html(), regex, 1);
			vulnerability
				.withOSVDBID((dbId.isEmpty()) ? null : new BigInteger(dbId));

			//CVE
	    		regex = "(?s)\\s*?<td>.*?<span.*?>CVE:</span>.*?</td>.*?<td>\\s*(.*?)\\s*</td>";
	    		String cve = findWithRegex(content.html(), regex, 1).replaceAll("<br\\s*/>", "");
			vulnerability
				.withCVEID((cve.isEmpty()) ? null : cve);
			
			//publishedDate
	    		regex = "(?s)\\s*?<td>.*?<span.*?>Published:</span>.*?</td>.*?<td>\\s*(.*?)\\s*</td>";
	    		String publishedTS = findWithRegex(content.html(), regex, 1);
			if (!publishedTS.isEmpty()) {
				calendar.setTimeInMillis(convertTimestamp(publishedTS));
				vulnerability
					.withPublishedDateTime(new DateTimeWithPrecisionType()
						.withValue(DatatypeFactory.newInstance().newXMLGregorianCalendar(calendar)));
	    		}

			/* software */
			regex = "(?s)\\s*?<td>.*?<span.*?>Vulnerable:</span>.*?</td>.*?<td>\\s*(.*?)\\s*</td>";
	    		String[] vulnerable = findWithRegex(content.html(), regex, 1).split("<br\\s*/>");
	    		trimAll(vulnerable);
	    		ArrayList<String> vulnerableList = new ArrayList<String>(Arrays.asList(vulnerable));
			//remove the plus and minus sub-entries.
			//see eg. http://www.securityfocus.com/bid/149/info
			String item;
			for(int i=vulnerableList.size()-1; i>=0; i--) {
				item = vulnerableList.get(i);
				if(item.equals("")){
					vulnerableList.remove(i);
				}else if(item.contains("<span class=\"related\">")) {
					vulnerableList.remove(i);
				}else if(item.equals("</span>")) {
					vulnerableList.remove(i);
				}else if(item.contains("</span>")) {
					vulnerableList.set(i, item.replaceAll("</span>\\s*", ""));
				}
			}

			for (int j = 0; j < vulnerableList.size(); j++) {
				Observable softwareObservable = setSoftwareObservable(vulnerableList.get(j), "Bugtraq");	
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
				stixPackage
					.withObservables(observables);
			}
 				

			//description
			doc = Jsoup.parse(discussion);
			content = doc.getElementById("vulnerability");
			if (!content.text().isEmpty()) {
				vulnerability
					.withDescriptions(new StructuredTextType()
						.withValue(content.text()));
			}

			//solution 
			doc = Jsoup.parse(solution);
			content = doc.getElementById("vulnerability");
			doc.getElementsByClass("title").first().remove();
			if (!content.text().isEmpty()) {
				CourseOfAction coa = setCourseOfAction("Vulnerability", content.text(), "Bugtraq");
				exploitTarget
					.withPotentialCOAs(new PotentialCOAsType()
						.withPotentialCOAs(new RelatedCourseOfActionType()
							.withCourseOfAction(new CourseOfAction()
								.withIdref(coa.getId()))));
				stixPackage
					.withCoursesOfAction(new CoursesOfActionType()
                                    		.withCourseOfActions(coa));
			}
				
			//references
			doc = Jsoup.parse(references);
			content = doc.getElementById("vulnerability");
			doc.getElementsByClass("title").first().remove();
			ArrayList<String> refStrings = findAllLinkHrefs(content);
			vulnerability
				.withReferences((refStrings.isEmpty()) ? null : new ReferencesType()
					.withReferences(refStrings));

			stixPackage 
				.withExploitTargets(new ExploitTargetsType()
					.withExploitTargets(exploitTarget
						.withId(new QName("gov.ornl.stucco", "vulnerability-" + UUID.randomUUID().toString(), "stucco"))
						.withTitle("Vulnerability")
						.withVulnerabilities(vulnerability
							.withSource("Bugtraq"))));
			
			return stixPackage;
		
		} catch (DatatypeConfigurationException e) {
			 e.printStackTrace();
		}
		
		return null;
	}
}
