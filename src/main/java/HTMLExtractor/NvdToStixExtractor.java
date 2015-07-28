/*
	Outputs NVD in STIX format containing the following fields:
		- CVE
		- CVSS Score
		- publishedDate
		- vulnerableSoftware
		- description
		- references
		- source 
*/

package HTMLExtractor;

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

import org.mitre.stix.exploittarget_1.VulnerabilityType;
import org.mitre.stix.exploittarget_1.CVSSVectorType;
import org.mitre.stix.common_1.ReferencesType;
import org.mitre.stix.common_1.StructuredTextType;
import org.mitre.stix.extensions.vulnerability.CVRF11InstanceType;
import org.mitre.stix.exploittarget_1.AffectedSoftwareType;
import org.mitre.stix.common_1.DateTimeWithPrecisionType;
import org.mitre.cybox.objects.Product;
import org.mitre.cybox.common_2.StringObjectPropertyType;
import org.mitre.cybox.common_2.ObjectPropertiesType;
import org.mitre.stix.common_1.RelatedObservableType;
import org.mitre.cybox.cybox_2.Observable;
import org.mitre.cybox.cybox_2.ObjectType;
import org.mitre.stix.common_1.ReferencesType;
import org.mitre.stix.common_1.InformationSourceType;
import org.mitre.stix.common_1.ExploitTargetsType;
import org.mitre.stix.common_1.ExploitTargetBaseType;
import org.mitre.stix.exploittarget_1.ExploitTarget;
import org.mitre.stix.exploittarget_1.PotentialCOAsType;
import org.mitre.stix.common_1.RelatedCourseOfActionType;
import org.mitre.stix.common_1.CourseOfActionBaseType;
import org.mitre.stix.courseofaction_1.CourseOfAction;
import org.mitre.cybox.common_2.TimeType;
import org.mitre.stix.stix_1.STIXHeaderType;
import org.mitre.stix.stix_1.STIXPackage;

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
import org.mitre.stix.exploittarget_1.ExploitTarget;
import org.mitre.stix.exploittarget_1.VulnerabilityType;
import org.mitre.stix.exploittarget_1.CVSSVectorType;
import org.mitre.stix.exploittarget_1.AffectedSoftwareType ;
import org.mitre.stix.indicator_2.Indicator;
import org.mitre.cybox.common_2.MeasureSourceType;
import org.mitre.cybox.common_2. StringObjectPropertyType;
import org.mitre.cybox.cybox_2.Observables;
import org.mitre.cybox.cybox_2.Observable;
import org.mitre.cybox.cybox_2.ObjectType;
import org.mitre.cybox.objects.Product;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.namespace.QName;				
import javax.xml.parsers.ParserConfigurationException;

import org.xml.sax.SAXException;			

public class NvdToStixExtractor extends HTMLExtractor	{
							
	private STIXPackage stixPackage;
	private static final Logger logger = LoggerFactory.getLogger(NvdToStixExtractor.class);
										
	//empty constractor for test purpose
	public NvdToStixExtractor(){};

	public NvdToStixExtractor(String nvdInfo)	{
		stixPackage = extract(nvdInfo);
	}
					
	public STIXPackage getStixPackage() {
		return stixPackage;
	}
	
	private long convertTimestamp(String time)	{ 
		return convertTimestamp(time + "(GMT)", "yyyy-MM-dd'T'HH:mm:ss.SSS-SS:SS");
	}

	private String makeSoftwareDesc(String cpe)	{
	
		String[] parts = cpe.split(":");
		String desc = new String();

		for (int i = 2; i < parts.length; i++)	{
			switch (i)	{
			case 2:	desc = parts[2];
				break;
			case 3: desc += " " + parts[3];
				break;
			case 4: desc += " version " + parts[4];
				break;
			case 5: desc += ", " + parts[5] + " language version";
				break;
			default: return desc;
			}
		}

		return desc;
	}
				
	private STIXPackage extract (String nvdInfo)	{
		
		try	{
			stixPackage = new STIXPackage();
			GregorianCalendar calendar = new GregorianCalendar();
			ExploitTargetsType ets = new ExploitTargetsType();
			IndicatorsType indicators = new IndicatorsType();
			Observables observables = new Observables()
				.withCyboxMajorVersion("2.0")
				.withCyboxMinorVersion("1.0");
			Map<String, QName> softwareMap = new HashMap<String, QName>();

			Document doc = Jsoup.parse(nvdInfo);
			Elements entries = doc.select("entry");
			
			for (Element entry : entries)	{

				VulnerabilityType vulnerability = new VulnerabilityType();
				QName exploitTargetId = new QName("gov.ornl.stucco", "vulnerability-" + UUID.randomUUID().toString(), "stucco");
	
				//description
				if (!entry.select("vuln|summary").isEmpty())
					vulnerability
						.withDescriptions(new StructuredTextType()              //list
 							.withValue(entry.select("vuln|summary").text()));				


				//cve
				if (!entry.select("vuln|cve-id").isEmpty())
					vulnerability
 						.withCVEID(entry.select("vuln|cve-id").text());
				else	
					vulnerability
 						.withCVEID(entry.select("entry").attr("id"));
				
	
				//CVSS Score
				if (!entry.select(" > vuln|cvss > cvss|base_metrics > cvss|score").isEmpty())
					vulnerability
 						.withCVSSScore(new CVSSVectorType()
							.withBaseScore(entry.select(" > vuln|cvss > cvss|base_metrics > cvss|score").text()));

				//publishedDate
				if (!entry.select("vuln|published-datetime").isEmpty())	{
					calendar.setTimeInMillis(convertTimestamp(entries.select("vuln|published-datetime").text()));	
					vulnerability
						.withPublishedDateTime(new DateTimeWithPrecisionType()
						.withValue(DatatypeFactory.newInstance().newXMLGregorianCalendar(calendar)));
				}

				//references
				Elements references = entry.select("vuln|references");
				if (!references.isEmpty())	{
				
					ReferencesType referencesType = new ReferencesType();
				
					for (Element reference : references)	{
						if(!reference.select("vuln|reference[href]").isEmpty())	
							referencesType
								.withReferences(reference.select("vuln|reference[href]").attr("href"));
						else
							referencesType
								.withReferences(reference.select("vuln|source").text() + ":" +
									reference.select("vuln|reference").text());
					}

					vulnerability
						.withReferences(referencesType);
				}

				//vulnerableSoftware
				Elements vulnerableSoftware = entry.select("vuln|vulnerable-software-list");
				if (!vulnerableSoftware.isEmpty())	{

					boolean addingNewSoftware = false;

					Elements softwareList = vulnerableSoftware.select("vuln|product");
					AffectedSoftwareType affectedSoftware = new AffectedSoftwareType();

					for (Element software : softwareList)	{
						
						String vulnSoftware = software.select("vuln|product").text();
						QName softwareId;

						if (softwareMap.containsKey(vulnSoftware))
							softwareId = softwareMap.get(vulnSoftware);
						else	{
							logger.debug(vulnSoftware);
							addingNewSoftware = true;
							softwareId = new QName("gov.ornl.stucco", "software-" + UUID.randomUUID().toString(), "stucco");
							softwareMap.put(vulnSoftware, softwareId);							

							//creating software observable
							observables
								.withObservables(new Observable()	
									.withTitle("Software")
									.withId(softwareId)
									.withObservableSources(new MeasureSourceType()
										.withName("NVD")
										.withInformationSourceType(new org.mitre.cybox.common_2.ControlledVocabularyStringType()
											.withValue("National Vulnerability Database")))
									.withObject(new ObjectType()	  //-> description ... description will go here
										.withDescription(new org.mitre.cybox.common_2.StructuredTextType()
											.withValue(makeSoftwareDesc(vulnSoftware)))
										.withProperties(new Product() 	//-> customFields
											.withProduct(new StringObjectPropertyType()
												.withValue(vulnSoftware)))));

							//creating a software indicator
							indicators
								.withIndicators(new Indicator()
									.withId(softwareId)
									.withTitle("Software")
									.withObservable(new Observable()
										.withIdref(softwareId))
									.withRelatedPackages(new RelatedPackageRefsType()
										.withPackageReferences(new RelatedPackageRefType()
											.withIdref(exploitTargetId)
											.withRelationship(new ControlledVocabularyStringType()
												.withValue("Has vulnerability")))));
						}

						//adding a reference to the affected software
						affectedSoftware	
							.withAffectedSoftwares(new RelatedObservableType()
                       						.withObservable(new Observable()
									.withIdref(softwareId)));
					}
				
					vulnerability
						.withAffectedSoftware(affectedSoftware);
				
				}

				ets
					.withExploitTargets(new ExploitTarget()
						.withId(exploitTargetId)
						.withTitle("Vulnerability")
						.withVulnerabilities(vulnerability
 							.withSource("NVD")));
			} 

			if (indicators.getIndicators().size() > 0)
				stixPackage
					.withIndicators(indicators)
					.withObservables(observables);	

			stixPackage
				.withId(new QName("gov.ornl.stucco", "NVD-" + UUID.randomUUID().toString(), "stucco"))
				.withTimestamp(DatatypeFactory.newInstance().newXMLGregorianCalendar(				
					new GregorianCalendar(TimeZone.getTimeZone("UTC"))))
				.withSTIXHeader(new STIXHeaderType()
					.withTitle("NVD"))           
				.withExploitTargets(ets);

			return stixPackage;

		} catch (DatatypeConfigurationException e)	{
			e.printStackTrace();
		}

		return null;
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
