package STIXExtractor;

import java.util.List;
import java.util.ArrayList;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.TimeZone;
import java.util.UUID;

import java.io.Reader;
import java.io.StringReader;
import java.io.IOException;

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
import org.mitre.cybox.cybox_2.Observables;
import org.mitre.cybox.cybox_2.Observable;
import org.mitre.cybox.cybox_2.ObjectType;
import org.mitre.cybox.cybox_2.RelatedObjectType;
import org.mitre.cybox.cybox_2.RelatedObjectsType;
import org.mitre.cybox.common_2.Property;
import org.mitre.cybox.common_2.ControlledVocabularyStringType;
import org.mitre.cybox.common_2.StringObjectPropertyType;
import org.mitre.cybox.common_2.StructuredTextType;
import org.mitre.cybox.common_2.DateTimeObjectPropertyType;
import org.mitre.cybox.objects.Hostname;
import org.mitre.cybox.objects.Product;
import org.mitre.cybox.objects.AccountObjectType;
import org.mitre.cybox.objects.UserAccountObjectType;
import org.mitre.cybox.objects.CategoryTypeEnum;
import org.mitre.cybox.objects.UserSession;

import org.xml.sax.SAXException;			

public class LoginEventExtractor extends HTMLExtractor	{
						
	private static final Logger logger = LoggerFactory.getLogger(LoginEventExtractor.class);
	private static final String[] HEADERS = {"date_time","hostname","login_software","status","user","from_ip"};
	private static final String DATE_TIME = "date_time";
	private static final String HOSTNAME = "hostname";
	private static final String LOGIN_SOFTWARE = "login_software";
	private static final String STATUS = "status";
	private static final String USER = "user";
	private static final String FROM_IP = "from_ip";
	
	private STIXPackage stixPackage;

	public LoginEventExtractor(String loginEventInfo)	{
		stixPackage = extract(loginEventInfo);
	}
					
	public STIXPackage getStixPackage() {
		return stixPackage;
	}

	private STIXPackage extract (String loginEventInfo)	{

		try	{

			CSVFormat csvFormat = CSVFormat.DEFAULT.withHeader(HEADERS);
			Reader reader = new StringReader(loginEventInfo);
			CSVParser csvParser = new CSVParser(reader, csvFormat);
			List<CSVRecord> records = csvParser.getRecords();
			
			if (records.size() == 0) return null;
			
			int start;
			CSVRecord record = records.get(0);
			if (record.get(0).equals(DATE_TIME))	{
				if (record.size() == 1) return null;
				else start = 1;
			}
			else start = 0;

			GregorianCalendar calendar = new GregorianCalendar();
			XMLGregorianCalendar now = DatatypeFactory.newInstance().newXMLGregorianCalendar(				
				new GregorianCalendar(TimeZone.getTimeZone("UTC")));
			stixPackage = new STIXPackage()				
 				.withSTIXHeader(new STIXHeaderType().
					withTitle("LoginEvent")) 
				.withTimestamp(now)
	 			.withId(new QName("gov.ornl.stucco", "LoginEvent-" + UUID.randomUUID().toString(), "stucco"));
			Observables observables = new Observables()
				.withCyboxMajorVersion("2.0")
				.withCyboxMinorVersion("1.0");

		 	for (int i = start; i < records.size(); i++)	{
			
				record = records.get(i);
				System.out.println(record);

				Observable hostnameObservable = null;
				Observable accountObservable = null;
				Observable softwareObservable = null;
				Observable hostAtIpObservable = null;
				Observable ipObservable = null;
				
				QName hostnameId = new QName("gov.ornl.stucco", "hostname-" + UUID.randomUUID().toString(), "stucco");
				QName accountId = new QName("gov.ornl.stucco", "account-" + UUID.randomUUID().toString(), "stucco");
				QName softwareId = new QName("gov.ornl.stucco", "software-" + UUID.randomUUID().toString(), "stucco");
				QName hostAtIpId = new QName("gov.ornl.stucco", "hostname-" + UUID.randomUUID().toString(), "stucco");
				QName ipId = new QName("gov.ornl.stucco", "ip-" + UUID.randomUUID().toString(), "stucco");

				//hostname
				if (!record.get(HOSTNAME).isEmpty())	{
					hostnameObservable = new Observable()	
						.withId(hostnameId)
						.withTitle("Hostname")
						.withObservableSources(getMeasureSourceType("LoginEvent"))
						.withObject(new ObjectType()
							.withId(new QName("gov.ornl.stucco", "hostname-" + record.get(HOSTNAME), "stucco"))
							.withDescription(new StructuredTextType()
								.withValue(record.get(HOSTNAME)))
							.withProperties(new Hostname()
								.withHostnameValue(new StringObjectPropertyType()
									.withValue(record.get(HOSTNAME)))));
			
					if (!record.get(LOGIN_SOFTWARE).isEmpty())
						hostnameObservable
							.getObject()
								.withRelatedObjects(new RelatedObjectsType()
									.withRelatedObjects(new RelatedObjectType()
										.withIdref(softwareId)
										.withDescription(new StructuredTextType()
											.withValue(record.get(HOSTNAME) + " runs " + record.get(LOGIN_SOFTWARE)))
										.withRelationship(new ControlledVocabularyStringType()
											.withValue("runs"))));
				
					observables
						.withObservables(hostnameObservable);
				}
				

				//account
				if (!record.get(USER).isEmpty())	{
					accountObservable = new Observable()	
						.withId(accountId)
						.withTitle("Account")
						.withObservableSources(getMeasureSourceType("LoginEvent"))
						.withObject(new ObjectType()
							.withId(new QName("gov.ornl.stucco", "account-" + record.get(USER), "stucco"))
							.withDescription(new StructuredTextType()
								.withValue(record.get(USER)))
							.withProperties(new UserAccountObjectType()
								.withUsername(new StringObjectPropertyType()
									.withValue(record.get(USER)))
								.withDescription(new StringObjectPropertyType()
									.withValue(record.get(USER)))));

					List<RelatedObjectType> relatedObjects = new ArrayList<RelatedObjectType>();
					if (!record.get(HOSTNAME).isEmpty())
						relatedObjects.add(
							new RelatedObjectType()
								.withIdref(hostnameId)
								.withDescription(new StructuredTextType()
									.withValue(record.get(USER) + " logs in to " + record.get(HOSTNAME))) 
								.withRelationship(new ControlledVocabularyStringType()
									.withValue("logsInTo"))
								.withState(new ControlledVocabularyStringType()
									.withValue(record.get(STATUS)))
								.withProperties(new UserSession()
									.withLoginTime(new DateTimeObjectPropertyType()
										.withValue(record.get(DATE_TIME)))));
					if (!record.get(FROM_IP).isEmpty())
						relatedObjects.add(
							new RelatedObjectType()
								.withIdref(hostAtIpId)
								.withDescription(new StructuredTextType()
									.withValue(record.get(USER) + " logs in from host at " + record.get(FROM_IP))) 
								.withRelationship(new ControlledVocabularyStringType()
									.withValue("logsInFrom"))
								.withState(new ControlledVocabularyStringType()
									.withValue(record.get(STATUS)))
								.withProperties(new UserSession()
									.withLoginTime(new DateTimeObjectPropertyType()
										.withValue(record.get(DATE_TIME)))));
					if (!relatedObjects.isEmpty())
					accountObservable
						.getObject()
							.withRelatedObjects(new RelatedObjectsType()
								.withRelatedObjects(relatedObjects));
					observables
						.withObservables(accountObservable);
				}

				//software
				if (!record.get(LOGIN_SOFTWARE).isEmpty())	{
					softwareObservable = new Observable()	
						.withId(softwareId)
						.withTitle("Software")
						.withObservableSources(getMeasureSourceType("LoginEvent"))
						.withObject(new ObjectType()
							.withId(new QName("gov.ornl.stucco", "software-" + record.get(LOGIN_SOFTWARE), "stucco"))
							.withDescription(new StructuredTextType()
								.withValue(record.get(LOGIN_SOFTWARE)))
							.withProperties(new Product()
								.withProduct(new StringObjectPropertyType()
									.withValue(record.get(LOGIN_SOFTWARE)))));
					observables
						.withObservables(softwareObservable);
				}
				
				//ip		
				if (!record.get(FROM_IP).isEmpty())	{
					ipObservable = new Observable()
						.withId(ipId)
						.withTitle("IP")
						.withObservableSources(getMeasureSourceType("LoginEvent"))
						.withObject(new ObjectType()
							.withId(new QName("gov.ornl.stucco", "ip-" + record.get(FROM_IP), "stucco"))
							.withDescription(new org.mitre.cybox.common_2.StructuredTextType()
								.withValue(record.get(FROM_IP))) 
							.withProperties(setAddress(record.get(FROM_IP), CategoryTypeEnum.IPV_4_ADDR)));
					observables
						.withObservables(ipObservable);		
				}
				//host
				if (!record.get(FROM_IP).isEmpty())	{
					hostAtIpObservable = new Observable()	
						.withId(hostAtIpId)
						.withTitle("Hostname")
						.withObservableSources(getMeasureSourceType("LoginEvent"))
						.withObject(new ObjectType()
							.withId(new QName("gov.ornl.stucco", "hostname-" + "host_at_" + record.get(FROM_IP), "stucco"))
							.withDescription(new StructuredTextType()
								.withValue("host at " + record.get(FROM_IP)))
							.withProperties(new Hostname()
								.withHostnameValue(new StringObjectPropertyType()
									.withValue("host_at_" + record.get(FROM_IP)))));
					if (!record.get(FROM_IP).isEmpty())
						hostAtIpObservable
							.getObject()
								.withRelatedObjects(new RelatedObjectsType()
									.withRelatedObjects(new RelatedObjectType()
										.withIdref(ipId)
										.withDescription(new StructuredTextType()
											.withValue("host at " + record.get(FROM_IP) + " has IP " + record.get(FROM_IP))) 
										.withRelationship(new ControlledVocabularyStringType()
											.withValue("hasIP"))
										.withState(new ControlledVocabularyStringType()
											.withValue(record.get(STATUS)))
										.withProperties(new UserSession()
											.withLoginTime(new DateTimeObjectPropertyType()
													.withValue(record.get(DATE_TIME))))));
					observables
						.withObservables(hostAtIpObservable);		
				}
			}
			stixPackage
				.withObservables(observables);
			System.out.println(stixPackage.toXMLString(true));

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
