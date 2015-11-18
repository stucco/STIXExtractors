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
				"20150712000033-ornl-ampDnsN4-1,42513,3,258,ornl,128.219.177.244,68.87.73.245,0,1,17,DALE-PC.ORNL.GOV,,,,,5n6unsmlboh476,2," +
				"2015-07-12 00:00:27+00,2015-07-12 00:00:27+00,US,oak ridge national laboratory,36.02103,84,US,comcast cable communications inc.," +	
				"38.6741,-77.4243,..,..,-91,-181";
		
			DNSRecordExtractor dnsExtractor = new DNSRecordExtractor(dnsInfo);
			STIXPackage stixPackage = dnsExtractor.getStixPackage();
			System.out.println(stixPackage.toXMLString(true));

			System.out.println("Validating DNS stixPackage");
			assertTrue(dnsExtractor.validate(stixPackage));
		
			Document stixDoc = Jsoup.parse(stixPackage.toXMLString(), "", Parser.xmlParser());		
			Element stixRecords = stixDoc.select("cybox|Observables").first();
			List<CSVRecord> csvRecords = getCSVRecordsList(HEADERS, dnsInfo);

			/* Testing DNS Record */
			for (int i = 1; i < csvRecords.size(); i++) {
				CSVRecord csvRecord = csvRecords.get(i);
				Element stixRecord = stixDoc.select("cybox|Observable:has(cybox|Event)").first();
				System.out.println();
				System.out.println("Testing DNS Record");
				System.out.println("Testing ID");
				assertEquals(stixRecord.select("DNSQueryObj|Transaction_ID").text(), csvRecord.get("recnum"));
				System.out.println("Testing Description");
				assertEquals(stixRecord.select("DNSRecordObj|Description").text(), 
						csvRecord.get("daddr") + " requested IP address of domain name " + ((!csvRecord.get("rqfqdn").isEmpty()) ? csvRecord.get("rqfqdn") : csvRecord.get("reqdn")));
				System.out.println("Testing QueriedDate");
				assertEquals(stixRecord.select("DNSRecordObj|Queried_Date").text(), csvRecord.get("last_seen_timet"));
				System.out.println("Testing DomainName");
				assertEquals(stixRecord.select("DNSRecordObj|Domain_Name > URIObj|Value").text(), ((!csvRecord.get("rqfqdn").isEmpty()) ? csvRecord.get("rqfqdn") : csvRecord.get("reqdn")));
				System.out.println("Testing IP Address");
				assertEquals(stixRecord.select("DNSRecordObj|IP_Address").text(), csvRecord.get("raddr"));
				System.out.println("Testing EntryType");
				assertEquals(stixRecord.select("DNSRecordObj|Entry_Type").text(), csvRecord.get("rqtype"));
				System.out.println("Testing TTL");
				assertEquals(stixRecord.select("DNSRecordObj|TTL").text(), csvRecord.get("ttl"));
				System.out.println("Testing Flags");
				assertEquals(stixRecord.select("DNSRecordObj|Flags").text(), csvRecord.get("flags"));
			
				Element saddr = stixRecord.select("cybox|Associated_Object:has(cybox|Association_Type:matches(^Address of responding DNS server$))").first();
				Element saddress = null;
				if (saddr != null) {
					System.out.println("Teting Source Address:");
					System.out.println("Teting Country Code");
					assertEquals(saddr.select("WhoisObj|Address").text(), csvRecord.get("scountrycode"));
					System.out.println("Teting Organization Name");
					assertEquals(saddr.select("WhoisObj|Organization").text(), csvRecord.get("sorganization"));
					System.out.println("Teting DNSRecord -> Source Address relation");
					String idref = saddr.select("WhoisObj|IP_Address").attr("object_reference");
					saddress = stixDoc.select("cybox|Observable[id=" + idref + "]").first();
					assertEquals(saddress.select("AddressObj|Address_Value").text(), csvRecord.get("saddr"));
				} else {
					if (!csvRecord.get("saddr").isEmpty()) {
						System.out.println("ERROR: Counld not find " + csvRecord.get("saddr"));
						assertTrue(false);
					} else {
						assertTrue(true);
					}
				}

				Element daddr = stixRecord.select("cybox|Associated_Object:has(cybox|Association_Type:matches(^Address of DNS requester$))").first();
				Element daddress = null;
				if (daddr != null) {
					System.out.println("Teting Destination Address:");
					System.out.println("Teting Country Code");
					assertEquals(saddr.select("WhoisObj|Address").text(), csvRecord.get("scountrycode"));
					System.out.println("Teting Organization Name");
					assertEquals(saddr.select("WhoisObj|Organization").text(), csvRecord.get("sorganization"));
					System.out.println("Teting DNSRecord -> Destination Address relation");
					String idref = daddr.select("WhoisObj|IP_Address").attr("object_reference");
					daddress = stixDoc.select("cybox|Observable[id=" + idref + "]").first();
					assertEquals(daddress.select("AddressObj|Address_Value").text(), csvRecord.get("daddr"));
				} else {
					if (!csvRecord.get("daddr").isEmpty()) {
						System.out.println("ERROR: Counld not find " + csvRecord.get("daddr"));
						assertTrue(false);
					} else {
						assertTrue(true);
					}
				}
				
				Element raddr = stixRecord.select("cybox|Associated_Object:has(cybox|Association_Type:matches(^Address of requested DNS$))").first();
				Element raddress = null;
				if (raddr != null) {
					System.out.println();
					System.out.println("Teting Requested Address:");
					System.out.println("Teting Country Code");
					assertEquals(saddr.select("WhoisObj|Address").text(), csvRecord.get("scountrycode"));
					System.out.println("Teting Organization Name");
					assertEquals(saddr.select("WhoisObj|Organization").text(), csvRecord.get("sorganization"));
					System.out.println("Teting DNSRecord -> Requested Address relation");
					String idref = raddr.select("WhoisObj|IP_Address").attr("object_reference");
					raddress = stixDoc.select("cybox|Observable[id=" + idref + "]").first();
					assertEquals(raddress.select("AddressObj|Address_Value").text(), csvRecord.get("raddr"));
				} else {
					if (!csvRecord.get("raddr").isEmpty()) {
						System.out.println("ERROR: Counld not find " + csvRecord.get("raddr"));
						assertTrue(false);
					} else {
						assertTrue(true);
					}
				}

				if (saddress != null) {
					System.out.println();
                  			System.out.println("Testing Source IP content:");
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
				}
				
				if (daddress != null) {
					System.out.println();
                  			System.out.println("Testing Destination IP content:");
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
				
				if (raddress != null) {
					System.out.println();
                  			System.out.println("Testing Requested IP content:");
                  			System.out.println("Testing Title");
                  			assertEquals(raddress.select("cybox|Title").text(), "IP");
                  			System.out.println("Testing Source");
                  			assertEquals(raddress.select("cyboxCommon|Information_Source_Type").text(), "DNSRecord");
                  			System.out.println("Testing IP Long (ID)");
                  			assertEquals(raddress.select("cybox|Object").attr("id"), "stucco:ip-" + ipToLong(csvRecord.get("raddr")));
                  			System.out.println("Testing IP String");
                  			assertEquals(raddress.select("AddressObj|Address_Value").text(), csvRecord.get("raddr"));
                  			System.out.println("Testing Description");
                  			assertEquals(raddress.select("cybox|Description").text(), csvRecord.get("raddr"));
				}
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
				CSVRecord csvRecord = csvRecords.get(i);
				Element stixRecord = stixDoc.select("cybox|Observable:has(cybox|Event)").first();
				System.out.println();
				System.out.println("Testing DNS Record");
				System.out.println("Testing ID");
				assertEquals(stixRecord.select("DNSQueryObj|Transaction_ID").text(), csvRecord.get("recnum"));
				System.out.println("Testing Description");
				assertEquals(stixRecord.select("DNSRecordObj|Description").text(), 
						csvRecord.get("daddr") + " requested IP address of domain name " + ((!csvRecord.get("rqfqdn").isEmpty()) ? csvRecord.get("rqfqdn") : csvRecord.get("reqdn")));
				System.out.println("Testing QueriedDate");
				assertEquals(stixRecord.select("DNSRecordObj|Queried_Date").text(), csvRecord.get("last_seen_timet"));
				System.out.println("Testing DomainName");
				assertEquals(stixRecord.select("DNSRecordObj|Domain_Name > URIObj|Value").text(), ((!csvRecord.get("rqfqdn").isEmpty()) ? csvRecord.get("rqfqdn") : csvRecord.get("reqdn")));
				System.out.println("Testing IP Address");
				assertEquals(stixRecord.select("DNSRecordObj|IP_Address").text(), csvRecord.get("raddr"));
				System.out.println("Testing EntryType");
				assertEquals(stixRecord.select("DNSRecordObj|Entry_Type").text(), csvRecord.get("rqtype"));
				System.out.println("Testing TTL");
				assertEquals(stixRecord.select("DNSRecordObj|TTL").text(), csvRecord.get("ttl"));
				System.out.println("Testing Flags");
				assertEquals(stixRecord.select("DNSRecordObj|Flags").text(), csvRecord.get("flags"));
			
				Element saddr = stixRecord.select("cybox|Associated_Object:has(cybox|Association_Type:matches(^Address of responding DNS server$))").first();
				Element saddress = null;
				if (saddr != null) {
					System.out.println("Teting Source Address:");
					System.out.println("Teting Country Code");
					assertEquals(saddr.select("WhoisObj|Address").text(), csvRecord.get("scountrycode"));
					System.out.println("Teting Organization Name");
					assertEquals(saddr.select("WhoisObj|Organization").text(), csvRecord.get("sorganization"));
					System.out.println("Teting DNSRecord -> Source Address relation");
					String idref = saddr.select("WhoisObj|IP_Address").attr("object_reference");
					saddress = stixDoc.select("cybox|Observable[id=" + idref + "]").first();
					assertEquals(saddress.select("AddressObj|Address_Value").text(), csvRecord.get("saddr"));
				} else {
					if (!csvRecord.get("saddr").isEmpty()) {
						System.out.println("ERROR: Counld not find " + csvRecord.get("saddr"));
						assertTrue(false);
					} else {
						assertTrue(true);
					}
				}

				Element daddr = stixRecord.select("cybox|Associated_Object:has(cybox|Association_Type:matches(^Address of DNS requester$))").first();
				Element daddress = null;
				if (daddr != null) {
					System.out.println("Teting Destination Address:");
					System.out.println("Teting Country Code");
					assertEquals(saddr.select("WhoisObj|Address").text(), csvRecord.get("scountrycode"));
					System.out.println("Teting Organization Name");
					assertEquals(saddr.select("WhoisObj|Organization").text(), csvRecord.get("sorganization"));
					System.out.println("Teting DNSRecord -> Destination Address relation");
					String idref = daddr.select("WhoisObj|IP_Address").attr("object_reference");
					daddress = stixDoc.select("cybox|Observable[id=" + idref + "]").first();
					assertEquals(daddress.select("AddressObj|Address_Value").text(), csvRecord.get("daddr"));
				} else {
					if (!csvRecord.get("daddr").isEmpty()) {
						System.out.println("ERROR: Counld not find " + csvRecord.get("daddr"));
						assertTrue(false);
					} else {
						assertTrue(true);
					}
				}
				
				Element raddr = stixRecord.select("cybox|Associated_Object:has(cybox|Association_Type:matches(^Address of requested DNS$))").first();
				Element raddress = null;
				if (raddr != null) {
					System.out.println();
					System.out.println("Teting Requested Address:");
					System.out.println("Teting Country Code");
					assertEquals(saddr.select("WhoisObj|Address").text(), csvRecord.get("scountrycode"));
					System.out.println("Teting Organization Name");
					assertEquals(saddr.select("WhoisObj|Organization").text(), csvRecord.get("sorganization"));
					System.out.println("Teting DNSRecord -> Requested Address relation");
					String idref = raddr.select("WhoisObj|IP_Address").attr("object_reference");
					raddress = stixDoc.select("cybox|Observable[id=" + idref + "]").first();
					assertEquals(raddress.select("AddressObj|Address_Value").text(), csvRecord.get("raddr"));
				} else {
					if (!csvRecord.get("raddr").isEmpty()) {
						System.out.println("ERROR: Counld not find " + csvRecord.get("raddr"));
						assertTrue(false);
					} else {
						assertTrue(true);
					}
				}

				if (saddress != null) {
					System.out.println();
                  			System.out.println("Testing Source IP content:");
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
				}
				
				if (daddress != null) {
					System.out.println();
                  			System.out.println("Testing Destination IP content:");
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
				
				if (raddress != null) {
					System.out.println();
                  			System.out.println("Testing Requested IP content:");
                  			System.out.println("Testing Title");
                  			assertEquals(raddress.select("cybox|Title").text(), "IP");
                  			System.out.println("Testing Source");
                  			assertEquals(raddress.select("cyboxCommon|Information_Source_Type").text(), "DNSRecord");
                  			System.out.println("Testing IP Long (ID)");
                  			assertEquals(raddress.select("cybox|Object").attr("id"), "stucco:ip-" + ipToLong(csvRecord.get("raddr")));
                  			System.out.println("Testing IP String");
                  			assertEquals(raddress.select("AddressObj|Address_Value").text(), csvRecord.get("raddr"));
                  			System.out.println("Testing Description");
                  			assertEquals(raddress.select("cybox|Description").text(), csvRecord.get("raddr"));
				}
			}		

		
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
}
