package STIXExtractor;

import java.util.List;
import java.util.ArrayList;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.TimeZone;
import java.util.UUID;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import java.io.Reader;
import java.io.StringReader;
import java.io.IOException;

import java.text.*;

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVRecord;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.namespace.QName;					
import javax.xml.parsers.ParserConfigurationException;

import org.mitre.stix.stix_1.STIXPackage;
import org.mitre.stix.stix_1.STIXHeaderType;
import org.mitre.stix.stix_1.TTPsType;
import org.mitre.stix.common_1.ControlledVocabularyStringType;
import org.mitre.stix.common_1.StructuredTextType;
import org.mitre.stix.common_1.InformationSourceType;
import org.mitre.stix.common_1.IdentityType;
import org.mitre.stix.common_1.ExploitTargetsType;
import org.mitre.stix.common_1.RelatedExploitTargetType;
import org.mitre.stix.ttp_1.TTP;
import org.mitre.stix.ttp_1.AttackPatternsType;
import org.mitre.stix.ttp_1.AttackPatternType;
import org.mitre.stix.ttp_1.ExploitType;
import org.mitre.stix.ttp_1.ExploitsType;
import org.mitre.stix.ttp_1.BehaviorType;
import org.mitre.stix.exploittarget_1.ExploitTarget;
import org.mitre.stix.exploittarget_1.VulnerabilityType;
import org.mitre.cybox.cybox_2.Observables;
import org.mitre.cybox.cybox_2.Observable;
import org.mitre.cybox.cybox_2.ObjectType;
import org.mitre.cybox.common_2.Property;

import org.xml.sax.SAXException;			

public class MetasploitExtractor extends HTMLExtractor	{
						
	private static final Logger logger = LoggerFactory.getLogger(MetasploitExtractor.class);
	private static final String[] HEADERS = {"id","mtime","file","mtype","refname","fullname","name","rank","description","license","privileged",
						"disclosure_date","default_target","default_action","stance","ready","ref_names","author_names"};
	private static final String ID = "id";
	private static final String MTYPE ="mtype";
	private static final String FULLNAME = "fullname";
	private static final String NAME = "name";
	private static final String DESCRIPTION = "description";
	private static final String REF_NAMES = "ref_names";
	
	private STIXPackage stixPackage;

	public MetasploitExtractor(String metasploitInfo)	{
		stixPackage = extract(metasploitInfo);
	}
					
	public STIXPackage getStixPackage() {
		return stixPackage;
	}

	private STIXPackage extract (String metasploitInfo)	{

		try	{
			CSVFormat csvFormat = CSVFormat.DEFAULT.withHeader(HEADERS);
			Reader reader = new StringReader(metasploitInfo);
			CSVParser csvParser = new CSVParser(reader, csvFormat);
			List<CSVRecord> records = csvParser.getRecords();
			
			if (records.size() == 0) return null;
			
			int start;
			CSVRecord record = records.get(0);

			if (record.get(0).equals(ID))	{
				if (record.size() == 1) return null;
				else start = 1;
			}
			else start = 0;

			GregorianCalendar calendar = new GregorianCalendar();
			XMLGregorianCalendar now = DatatypeFactory.newInstance().newXMLGregorianCalendar(				
				new GregorianCalendar(TimeZone.getTimeZone("UTC")));
			stixPackage = new STIXPackage()				
 				.withSTIXHeader(new STIXHeaderType().
					withTitle("Metasploit")) 
				.withTimestamp(now)
	 			.withId(new QName("gov.ornl.stucco", "Metasploit-" + UUID.randomUUID().toString(), "stucco"));
			ExploitTargetsType ets = new ExploitTargetsType();
			TTPsType ttps = new TTPsType();

			for (int i = start; i < records.size(); i++)	{
				record = records.get(i);

				//malware
				ExploitType exploit = new ExploitType();
				AttackPatternsType attackPattern = new AttackPatternsType();
				BehaviorType behavior = new BehaviorType();
				boolean withExploit = false;

				if (!record.get(FULLNAME).isEmpty())	{
					exploit
						.withTitle(record.get(FULLNAME));
					withExploit = true;
				}
				
				if (!record.get(MTYPE).isEmpty())	{
					exploit
						.withId(new QName("gov.ornl.stucco", record.get(MTYPE) + "-" + UUID.randomUUID().toString(), "stucco"));
					withExploit = true;
					
				}
				
				if (!record.get(NAME).isEmpty())	{
					exploit
						.withShortDescriptions(new StructuredTextType() 	//list
							.withValue(record.get(NAME)));
					withExploit = true;
				}

				if (!record.get(DESCRIPTION).isEmpty())	{
					exploit
						.withDescriptions(new StructuredTextType()	//list
							.withValue(record.get(DESCRIPTION)));
					withExploit = true;
				}

				if (withExploit)
					behavior 
						.withExploits(new ExploitsType()
							.withExploits(exploit));
				
				//vulnerability
				List<RelatedExploitTargetType> relatedEt = new ArrayList<RelatedExploitTargetType>();
				boolean withEt = false;
				Pattern pattern = Pattern.compile("CVE-\\d{4}-\\d{4,7}");
				Matcher matcher = pattern.matcher(record.get(REF_NAMES));

				while(matcher.find())	{
					QName etId = new QName("gov.ornl.stucco", "vulnerability-" + UUID.randomUUID().toString(), "stucco");
					ets
						.withExploitTargets(new ExploitTarget()
							.withId(etId)
							.withTitle("Vulnerability")
							.withVulnerabilities(new VulnerabilityType()	//list
								.withCVEID(matcher.group())
								.withTitle(matcher.group())
								.withDescriptions(new StructuredTextType()	//list
									.withValue(matcher.group()))
								.withSource("Metasploit")));

					relatedEt.add(
						new RelatedExploitTargetType()	
							.withExploitTarget(new ExploitTarget()
								.withIdref(etId))
							.withRelationship(new ControlledVocabularyStringType()
								.withValue("exploit")));
						
					withEt = true;
				}
				
				//if malware exists, then packing it and adding references to vulnerabilities
				if (withExploit)	{
					TTP ttp = new TTP()
						.withTitle("Malware")
						.withInformationSource(new InformationSourceType()
							.withIdentity(new IdentityType()
								.withName("Metasploit")))
						.withBehavior(behavior);
					if (withEt)
						ttp 
							.withExploitTargets(new org.mitre.stix.ttp_1.ExploitTargetsType()
								.withExploitTargets(relatedEt));
					ttps
						.withTTPS(ttp);
				}
			}

			if (!ets.getExploitTargets().isEmpty())
				stixPackage
					.withExploitTargets(ets);

			if (!ttps.getTTPS().isEmpty())
				stixPackage
					.withTTPs(ttps);

		} catch (DatatypeConfigurationException e)	{
			e.printStackTrace();
		} 
		catch (IOException e)	{
			e.printStackTrace();
		}

		return stixPackage;
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
