package STIXExtractor;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Set;
import java.util.TreeSet;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.parser.Tag;
import org.jsoup.select.Elements;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.mitre.stix.stix_1.STIXPackage;
import org.mitre.stix.stix_1.IndicatorsType;
import org.mitre.stix.stix_1.CoursesOfActionType;
import org.mitre.stix.stix_1.TTPsType;
import org.mitre.stix.ttp_1.TTP;
import org.mitre.stix.ttp_1.BehaviorType;
import org.mitre.stix.ttp_1.MalwareType;
import org.mitre.stix.ttp_1.MalwareInstanceType;
import org.mitre.stix.ttp_1.AttackPatternsType;
import org.mitre.stix.ttp_1.AttackPatternType;
import org.mitre.stix.ttp_1.VictimTargetingType;
import org.mitre.stix.common_1.ControlledVocabularyStringType;
import org.mitre.stix.common_1.StructuredTextType;
import org.mitre.stix.courseofaction_1.CourseOfAction;

import javax.xml.datatype.DatatypeConfigurationException;

public class FSecureExtractor extends STIXExtractor {
	
	private static final Logger logger = LoggerFactory.getLogger(FSecureExtractor.class);

	private STIXPackage stixPackage;
										
	public FSecureExtractor(String pageContent) {
		stixPackage = extractStixPackage(pageContent);
	}
	
	public STIXPackage getStixPackage() {
		return stixPackage;
	}
	
	//This makes <p><b> text into <h4> text.
	//They are equivalent, but not used consistently between pages.
	private static void fixSectionHeaders(Elements contents) {
		Element curr, replacement;
		Elements currChildren;
		for(int i = contents.size()-1; i>=0; i--) {
			curr = contents.get(i);
			if(curr.tagName().equals("p")) {
				currChildren = curr.children();
				if(currChildren.size() == 1 && currChildren.get(0).tagName().equalsIgnoreCase("b")) {
					replacement = new Element(Tag.valueOf("h4"), "");
					replacement.text(curr.text());
					contents.remove(i);
					contents.add(i, replacement);
				}
			}
		}
	}
						
	private STIXPackage extractStixPackage(String pageContent) {
		try {
			Document doc = Jsoup.parse(pageContent);

			stixPackage = initStixPackage("F-Secure");
			TTP ttp = initTTP("F-Secure");
			MalwareInstanceType malware = new MalwareInstanceType();
			AttackPatternsType attackPatterns = new AttackPatternsType();

			//name + alias
			String vertexName = doc.getElementsByTag("title").first().text().replaceAll("\u200b", "").replaceAll("\\:\\?",":");
			if (!vertexName.isEmpty()) {
				malware
					.withTitle(vertexName);
			}
			Element detailsTable = doc.getElementsByClass("details-table").first();
			String[][] cells = getCells(detailsTable.getElementsByTag("tr"));
			String aliases = cells[0][1];
			String category = cells[1][1];
			String type = cells[2][1];
			String platform = cells[3][1];
			String[] aliasList = aliases.split(", ");
			Set<String> aliasSet = new TreeSet<String>();
			aliasSet.add(vertexName);
			for (String alias : aliasList) {
				aliasSet.add(alias.replaceAll("\u200b", "").replaceAll("\\:\\?",":"));
			}
			for (String alias : aliasSet) {
				malware
					.withNames(new ControlledVocabularyStringType()
							.withValue(alias));
			}

			malware
				.withTypes((category.isEmpty()) ? null : new ControlledVocabularyStringType()
					.withValue(category))
				.withTypes((type.isEmpty()) ? null : new ControlledVocabularyStringType()
					.withValue(type));
			
			Element contentDiv = doc.select("div#maincontent").first().select("div.row").first().select("div").first();
			Elements contents = contentDiv.children().first().children();
			Element curr, prev;
			removeBRs(contents);
			removeHRs(contents);
			fixSectionHeaders(contents);
			for(int i = contents.size()-1; i>0; i--){
				curr = contents.get(i);
				prev = contents.get(i-1);
				if(curr.tagName().equals("p") && prev.tagName().equals("p")){
					prev.text( prev.text() + "\n" + curr.text() );
					contents.remove(i);
					continue;
				}
				if(curr.tagName().equals("p") && prev.tagName().equals("ul")){
					curr.text( ulToString(prev) + "\n" + curr.text() );
					contents.remove(i-1);
					continue;
				}
				if(curr.tagName().equals("p") && prev.tagName().equals("img")){
					curr.text( prev.attr("src") + "\n" + curr.text() );
					contents.remove(i-1);
					continue;
				}

				//details
				if(curr.tagName().equals("p") && prev.tagName().equals("h2") && prev.text().equals("Technical Details")){
					attackPatterns
						.withAttackPatterns(new AttackPatternType()
						.withTitle("Details")
						.withDescriptions(new StructuredTextType()
							.withValue(curr.text())));
					contents.remove(i);
					contents.remove(i-1);
					i--;
					continue;
				}

				//description
				if(curr.tagName().equals("p") && prev.tagName().equals("h2") && prev.text().equals("Summary")){
					malware
						.withDescriptions(new StructuredTextType()
								.withValue(curr.text()));
					contents.remove(i);
					contents.remove(i-1);
					i--;
					continue;
				}

				//course of action
				if(curr.tagName().equals("p") && prev.tagName().equals("h5") && prev.text().equals("Automatic action")){
					String removalMessage = curr.text();
					if(removalMessage.startsWith("Once detected, the F-Secure security product will automatically disinfect the suspect file")){
						CourseOfAction coa = setCourseOfAction("Malware", "F-Secure", "F-Secure");
						stixPackage
							.withCoursesOfAction(new CoursesOfActionType()
									.withCourseOfActions(coa))
							.withIndicators(new IndicatorsType()
									.withIndicators(setMalwareCoaIndicator(ttp.getId(), coa.getId(), "F-Secure")));
					}else{
						CourseOfAction coa = setCourseOfAction("Malware", "F-Secure: " + removalMessage, "F-Secure");
						stixPackage
							.withCoursesOfAction(new CoursesOfActionType()
									.withCourseOfActions(coa))
							.withIndicators(new IndicatorsType()
									.withIndicators(setMalwareCoaIndicator(ttp.getId(), coa.getId(), "F-Secure")));
					}
					contents.remove(i);
					contents.remove(i-1);
					contents.remove(i-2);
					i -= 2;
					continue;
				}

				//distribution
				if(curr.tagName().equals("p") && prev.tagName().equals("h4") && prev.text().equals("Distribution")){
					attackPatterns
						.withAttackPatterns(new AttackPatternType()
							.withTitle("Distribution")
							.withDescriptions(new StructuredTextType()
								.withValue(curr.text())));
					contents.remove(i);
					contents.remove(i-1);
					i -= 1;
					continue;
				}

				//behavior
				if(curr.tagName().equals("p") && prev.tagName().equals("h4") && prev.text().equals("Behavior")){
					attackPatterns
						.withAttackPatterns(new AttackPatternType()
							.withTitle("Behavior")
							.withDescriptions(new StructuredTextType()
								.withValue(curr.text())));
					contents.remove(i);
				contents.remove(i-1);
				i -= 1;
				continue;
				}
				if(curr.tagName().equals("p") && (prev.tagName().equals("h5") || prev.tagName().equals("h4")) && prev.text().equals("More")){
					contents.remove(i);
					contents.remove(i-1);
					i -= 1;
					continue;
				}
			}
		
			return stixPackage
				.withTTPs(new TTPsType()
					.withTTPS(ttp
						.withVictimTargeting((platform.isEmpty()) ? null : new VictimTargetingType()
							.withTargetedSystems(new ControlledVocabularyStringType()
								.withValue(platform)))
						.withBehavior(new BehaviorType()
							.withAttackPatterns((attackPatterns.getAttackPatterns().isEmpty()) ? null : attackPatterns)
							.withMalware(new MalwareType()
								.withMalwareInstances(malware)))));
			
		} catch (DatatypeConfigurationException e) {
			 e.printStackTrace();
		}	
	
		return null;
	}

	private static String ulToString(Element ul) {
		String ret;
		ret = ul.text();
		logger.debug(":::ulToString is returning::: {}", ret);
		return ret;
	}
}
