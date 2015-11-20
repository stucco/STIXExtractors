package STIXExtractor;

import java.util.List;

import java.io.IOException;

import org.apache.commons.csv.CSVRecord;

import org.jsoup.parser.Parser;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import org.mitre.stix.stix_1.STIXPackage;

import org.junit.Test;

import static org.junit.Assert.*;

import STIXExtractor.DNSRecordExtractor;

/**
 * Unit test for Argus Extractor.
 */
public class DNSRecordExtractorTest extends STIXExtractor {
	
	/**
	 * Test one element
	 */
	@Test
	public void test_one_element_with_header() {
		try {
			System.out.println("STIXExtractor.DNSRecordExtractor.test_one_element_with_header()");

			String headers = 
				"filename,recnum,file_type,amp_version,site,saddr,daddr,ttl,rqtype,flags,rqfqdn,refqdn,raddr,preference," +	
				"answer_ns,authoritative_ns,times_seen,first_seen_timet,last_seen_timet,scountrycode,sorganization,slat,slong," +
				"dcountrycode,dorganization,dlat,dlong,rcountrycode,rorganization,rlat,rlong";
			String[] HEADERS = headers.split(",");
			String dnsInfo = 
				"filename,recnum,file_type,amp_version,site,saddr,daddr,ttl,rqtype,flags,rqfqdn,refqdn,raddr,preference," +	
				"answer_ns,authoritative_ns,times_seen,first_seen_timet,last_seen_timet,scountrycode,sorganization,slat,slong," +
				"dcountrycode,dorganization,dlat,dlong,rcountrycode,rorganization,rlat,rlong\n" +
				"20150712000033-ornl-ampDnsN4-1,42513,3,258,ornl,128.219.177.244,68.87.73.245,0,1,17,DALE-PC.ORNL.GOV,,89.79.77.77,,,5n6unsmlboh476,2," +
				"2015-07-12 00:00:27+00,2015-07-12 00:00:27+00,US,oak ridge national laboratory,36.02103,84,US,comcast cable communications inc.," +	
				"38.6741,-77.4243,..,..,-91,-181";
		
			DNSRecordExtractor dnsExtractor = new DNSRecordExtractor(dnsInfo);
			STIXPackage stixPackage = dnsExtractor.getStixPackage();

			System.out.println("Validating DNS stixPackage");
			assertTrue(dnsExtractor.validate(stixPackage));
		
			Document stixDoc = Jsoup.parse(stixPackage.toXMLString(), "", Parser.xmlParser());		
			Element stixRecords = stixDoc.select("cybox|Observables").first();
			List<CSVRecord> csvRecords = getCSVRecordsList(HEADERS, dnsInfo);

			/* Testing DNS Record */
			for (int i = 1; i < csvRecords.size(); i++) {
				CSVRecord csvRecord = csvRecords.get(i);
				Element stixRecord = stixDoc.select("cybox|Observable:has(DNSRecordObj|Description").first();
				System.out.println();
				System.out.println("Testing DNS Record");
				System.out.println("Testing Description");
				assertEquals(stixRecord.select("DNSRecordObj|Description").text(), "Requested domain name " + csvRecord.get("rqfqdn") + " resolved to IP address " + csvRecord.get("raddr"));
				System.out.println("Testing QueriedDate");
				assertEquals(stixRecord.select("DNSRecordObj|Queried_Date").text(), csvRecord.get("last_seen_timet"));
				System.out.println("Testing EntryType");
				assertEquals(stixRecord.select("DNSRecordObj|Entry_Type").text(), csvRecord.get("rqtype"));
				System.out.println("Testing TTL");
				assertEquals(stixRecord.select("DNSRecordObj|TTL").text(), csvRecord.get("ttl"));
				System.out.println("Testing Flags");
				assertEquals(stixRecord.select("DNSRecordObj|Flags").text(), csvRecord.get("flags"));

				System.out.println();
				System.out.println("Testing DNSName");
				String dnsId = stixRecord.select("DNSRecordObj|Domain_Name").attr("object_reference");
				Element dnsElement = stixDoc.select("cybox|Observable[id=" + dnsId + "]").first();
				System.out.println("Testing Title");
				assertEquals(dnsElement.select("cybox|title").text(), "DNSName");
				System.out.println("Testing Name");
				assertEquals(dnsElement.select("DomainNameObj|Value").text(), csvRecord.get("rqfqdn"));
				System.out.println("Testing Description");
				assertEquals(dnsElement.select("cybox|description").text(), csvRecord.get("rqfqdn"));
				System.out.println("Testing Source");
				assertEquals(dnsElement.select("cyboxcommon|information_source_type").text(), "DNSRecord");
		
				System.out.println();
				System.out.println("Testing Requested IP Address");
				String ipId = stixRecord.select("DNSRecordObj|IP_Address").attr("object_reference");
				Element ipElement = stixDoc.select("cybox|Observable[id=" + ipId + "]").first();
				System.out.println("Testing Title");
				assertEquals(ipElement.select("cybox|Title").text(), "IP");
				System.out.println("Testing Source");
				assertEquals(ipElement.select("cyboxCommon|Information_Source_Type").text(), "DNSRecord");
				System.out.println("Testing IP Long (ID)");
				assertEquals(ipElement.select("cybox|Object").attr("id"), "stucco:ip-" + ipToLong(csvRecord.get("raddr")));
				System.out.println("Testing IP String");
				assertEquals(ipElement.select("AddressObj|Address_Value").text(), csvRecord.get("raddr"));
				System.out.println("Testing Description");
				assertEquals(ipElement.select("cybox|Description").text(), csvRecord.get("raddr"));

				System.out.println();
                  		System.out.println("Testing Source IP content:");
				String sId = stixRecord.select("cybox|Related_Object:has(cybox|Relationship:matches(^Served_By))").first().attr("idref");
				Element saddress = stixDoc.select("cybox|Observable[id=" + sId +"]").first();
                  		System.out.println("Testing Title");
                  		assertEquals(saddress.select("cybox|Title").text(), "IP");
                  		System.out.println("Testing Source");
                  		assertEquals(saddress.select("cyboxCommon|Information_Source_Type").text(), "DNSRecord");
                  		System.out.println("Testing IP Long (ID)");
                  		assertEquals(saddress.select("cybox|Object").attr("id"), "stucco:ip-" + ipToLong(csvRecord.get("saddr")));
                  		System.out.println("Testing IP String");
                  		assertEquals(saddress.select("AddressObj|Address_Value").text(), csvRecord.get("saddr"));
                  		System.out.println("Testing Description");
                  		assertEquals(saddress.select("cybox|Description").text(), csvRecord.get("saddr"));

				System.out.println();
                  		System.out.println("Testing Destination IP content:");
				String dId = stixRecord.select("cybox|Related_Object:has(cybox|Relationship:matches(^Requested_By))").first().attr("idref");
				Element daddress = stixDoc.select("cybox|Observable[id=" + dId +"]").first();
                  		System.out.println("Testing Title");
                  		assertEquals(daddress.select("cybox|Title").text(), "IP");
                  		System.out.println("Testing Source");
                  		assertEquals(daddress.select("cyboxCommon|Information_Source_Type").text(), "DNSRecord");
                  		System.out.println("Testing IP Long (ID)");
                  		assertEquals(daddress.select("cybox|Object").attr("id"), "stucco:ip-" + ipToLong(csvRecord.get("daddr")));
                  		System.out.println("Testing IP String");
                  		assertEquals(daddress.select("AddressObj|Address_Value").text(), csvRecord.get("daddr"));
                  		System.out.println("Testing Description");
                  		assertEquals(daddress.select("cybox|Description").text(), csvRecord.get("daddr"));
			}
				
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	/**
	 * Test two elements
	 */
	@Test
	public void test_two_elements_with_header() {
		try {
			System.out.println("STIXExtractor.DNSRecordExtractor.test_two_elements_with_header()");

			String headers = 
				"filename,recnum,file_type,amp_version,site,saddr,daddr,ttl,rqtype,flags,rqfqdn,refqdn,raddr,preference," +	
				"answer_ns,authoritative_ns,times_seen,first_seen_timet,last_seen_timet,scountrycode,sorganization,slat,slong," +
				"dcountrycode,dorganization,dlat,dlong,rcountrycode,rorganization,rlat,rlong";
			String[] HEADERS = headers.split(",");
			String dnsInfo = 
				"filename,recnum,file_type,amp_version,site,saddr,daddr,ttl,rqtype,flags,rqfqdn,refqdn,raddr,preference," +	
				"answer_ns,authoritative_ns,times_seen,first_seen_timet,last_seen_timet,scountrycode,sorganization,slat,slong," +
				"dcountrycode,dorganization,dlat,dlong,rcountrycode,rorganization,rlat,rlong\n" +
				"20150712000225-ornl-ampDnsA4-1,7016,2,258,ornl,199.7.83.42,160.91.86.22,172800,1,3,a.in-addr-servers.arpa,,199.212.0.73,,,," +	
				"2015-07-12 00:00:01+00,2015-07-12 00:00:01+00,US,icann,34.0634,-118.2393,US,oak ridge national laboratory,36.02103,-84.25273,zzz" +	
				"US,arin operations,38.90825,-77.51781";
		
			DNSRecordExtractor dnsExtractor = new DNSRecordExtractor(dnsInfo);
			STIXPackage stixPackage = dnsExtractor.getStixPackage();
			
			System.out.println("Validating DNS stixPackage");
			assertTrue(dnsExtractor.validate(stixPackage));
		
			Document stixDoc = Jsoup.parse(stixPackage.toXMLString(), "", Parser.xmlParser());		
			List<CSVRecord> csvRecords = getCSVRecordsList(HEADERS, dnsInfo);

			/* Testing DNS Record */
			for (int i = 1; i < csvRecords.size(); i++) {
				System.out.println();
				CSVRecord csvRecord = csvRecords.get(i);
				String description = "^Requested domain name " + csvRecord.get("rqfqdn") + " resolved to IP address " + csvRecord.get("raddr");
				Element stixRecord = stixDoc.select("cybox|Observable:has(DNSRecordObj|Description:matches(" + description + "))").first(); 
				System.out.println("Testing DNS Record");
				System.out.println("Testing Description");
				assertEquals(stixRecord.select("DNSRecordObj|Description").text(), "Requested domain name " + csvRecord.get("rqfqdn") + " resolved to IP address " + csvRecord.get("raddr"));
				System.out.println("Testing QueriedDate");
				assertEquals(stixRecord.select("DNSRecordObj|Queried_Date").text(), csvRecord.get("last_seen_timet"));
				System.out.println("Testing EntryType");
				assertEquals(stixRecord.select("DNSRecordObj|Entry_Type").text(), csvRecord.get("rqtype"));
				System.out.println("Testing TTL");
				assertEquals(stixRecord.select("DNSRecordObj|TTL").text(), csvRecord.get("ttl"));
				System.out.println("Testing Flags");
				assertEquals(stixRecord.select("DNSRecordObj|Flags").text(), csvRecord.get("flags"));

				System.out.println();
				System.out.println("Testing DNSName");
				String dnsId = stixRecord.select("DNSRecordObj|Domain_Name").attr("object_reference");
				Element dnsElement = stixDoc.select("cybox|Observable[id=" + dnsId + "]").first();
				System.out.println("Testing Title");
				assertEquals(dnsElement.select("cybox|title").text(), "DNSName");
				System.out.println("Testing Name");
				assertEquals(dnsElement.select("DomainNameObj|Value").text(), csvRecord.get("rqfqdn"));
				System.out.println("Testing Description");
				assertEquals(dnsElement.select("cybox|description").text(), csvRecord.get("rqfqdn"));
				System.out.println("Testing Source");
				assertEquals(dnsElement.select("cyboxcommon|information_source_type").text(), "DNSRecord");
		
				System.out.println();
				System.out.println("Testing Requested IP Address");
				String ipId = stixRecord.select("DNSRecordObj|IP_Address").attr("object_reference");
				Element ipElement = stixDoc.select("cybox|Observable[id=" + ipId + "]").first();
				System.out.println("Testing Title");
				assertEquals(ipElement.select("cybox|Title").text(), "IP");
				System.out.println("Testing Source");
				assertEquals(ipElement.select("cyboxCommon|Information_Source_Type").text(), "DNSRecord");
				System.out.println("Testing IP Long (ID)");
				assertEquals(ipElement.select("cybox|Object").attr("id"), "stucco:ip-" + ipToLong(csvRecord.get("raddr")));
				System.out.println("Testing IP String");
				assertEquals(ipElement.select("AddressObj|Address_Value").text(), csvRecord.get("raddr"));
				System.out.println("Testing Description");
				assertEquals(ipElement.select("cybox|Description").text(), csvRecord.get("raddr"));

				System.out.println();
                  		System.out.println("Testing Source IP content:");
				String sId = stixRecord.select("cybox|Related_Object:has(cybox|Relationship:matches(^Served_By))").first().attr("idref");
				Element saddress = stixDoc.select("cybox|Observable[id=" + sId +"]").first();
                  		System.out.println("Testing Title");
                  		assertEquals(saddress.select("cybox|Title").text(), "IP");
                  		System.out.println("Testing Source");
                  		assertEquals(saddress.select("cyboxCommon|Information_Source_Type").text(), "DNSRecord");
                  		System.out.println("Testing IP Long (ID)");
                  		assertEquals(saddress.select("cybox|Object").attr("id"), "stucco:ip-" + ipToLong(csvRecord.get("saddr")));
                  		System.out.println("Testing IP String");
                  		assertEquals(saddress.select("AddressObj|Address_Value").text(), csvRecord.get("saddr"));
                  		System.out.println("Testing Description");
                  		assertEquals(saddress.select("cybox|Description").text(), csvRecord.get("saddr"));

				System.out.println();
                  		System.out.println("Testing Destination IP content:");
				String dId = stixRecord.select("cybox|Related_Object:has(cybox|Relationship:matches(^Requested_By))").first().attr("idref");
				Element daddress = stixDoc.select("cybox|Observable[id=" + dId +"]").first();
                  		System.out.println("Testing Title");
                  		assertEquals(daddress.select("cybox|Title").text(), "IP");
                  		System.out.println("Testing Source");
                  		assertEquals(daddress.select("cyboxCommon|Information_Source_Type").text(), "DNSRecord");
                  		System.out.println("Testing IP Long (ID)");
                  		assertEquals(daddress.select("cybox|Object").attr("id"), "stucco:ip-" + ipToLong(csvRecord.get("daddr")));
                  		System.out.println("Testing IP String");
                  		assertEquals(daddress.select("AddressObj|Address_Value").text(), csvRecord.get("daddr"));
                  		System.out.println("Testing Description");
                  		assertEquals(daddress.select("cybox|Description").text(), csvRecord.get("daddr"));
			}
				
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
}
