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

import STIXExtractor.HTTPDataExtractor;

/**
 * Unit test for HTTPDataExtractor.
 */
public class HTTPDataExtractorTest extends STIXUtils {
	
	/**
	 * Test empty document
	 */
	@Test
	public void test_empty_doc() {
			 
		System.out.println();
		System.out.println("STIXExtractor.HTTPDataExtractorTest.test_empty_doc()");

		String httpInfo = "";

		HTTPDataExtractor httpExtractor = new HTTPDataExtractor(httpInfo);
		STIXPackage stixPackage = httpExtractor.getStixPackage();

		System.out.println("Testing that STIXPackage is null");
		assertTrue(stixPackage == null);
	}

	/**
	 * Test empty element
	 */
	@Test
	public void test_empty_element() {
			
		System.out.println();
		System.out.println("STIXExtractor.HTTPDataExtractorTest.test_empty_element()");

		String httpInfo = 
			"filename,recnum,file_type,amp_version,site,saddr,daddr,request_len,dport,times_seen,first_seen_timet," +
 			"last_seen_timet,method,request,query_terms,accept_language,user_agent,server_fqdn,referer,uri,clean_data," +
 			"full_data,scountrycode,sorganization,slat,slong,dcountrycode,dorganization,dlat,dlong,distance\n" +
			",,,,,,,,,,,,,,,,,,,,,,,,,,,,,,";

		HTTPDataExtractor httpExtractor = new HTTPDataExtractor(httpInfo);
		STIXPackage stixPackage = httpExtractor.getStixPackage();

		System.out.println("Testing that STIXPackage is null");
		assertTrue(stixPackage == null);
	}
	
	/**
	 * Test element with just header
	 */
	@Test
	public void test_element_with_header() {
			
		System.out.println();
		System.out.println("STIXExtractor.HTTPDataExtractorTest.test_element_with_header()");

		String httpInfo = 
			"filename,recnum,file_type,amp_version,site,saddr,daddr,request_len,dport,times_seen,first_seen_timet," +
 			"last_seen_timet,method,request,query_terms,accept_language,user_agent,server_fqdn,referer,uri,clean_data," +
 			"full_data,scountrycode,sorganization,slat,slong,dcountrycode,dorganization,dlat,dlong,distance";
		
		HTTPDataExtractor httpExtractor = new HTTPDataExtractor(httpInfo);
		STIXPackage stixPackage = httpExtractor.getStixPackage();

		System.out.println("Testing that STIXPackage is null");
		assertTrue(stixPackage == null);
	}

	/**
	 * Test one element
	 */
	@Test
	public void test_one_element_with_header() {
			
		System.out.println();
		System.out.println("STIXExtractor.HTTPDataExtractorTest.test_one_element_with_header()");

		String httpInfo = 
			"filename,recnum,file_type,amp_version,site,saddr,daddr,request_len,dport,times_seen,first_seen_timet," +
 			"last_seen_timet,method,request,query_terms,accept_language,user_agent,server_fqdn,referer,uri,clean_data," +
 			"full_data,scountrycode,sorganization,slat,slong,dcountrycode,dorganization,dlat,dlong,distance \n" +
			"20150909000417-ornl-ampHttpR4-1,5763,1,2,ornl,128.219.49.13,54.192.138.232,846,80,1,2015-09-09 00:03:09+00,2015-09-09 00:03:09+00," +
			"GET,/tv2n/vpaid/8bc5b7b,[],\"en-US,en;q=0.8\",\"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36\"," +
			"cdn455.telemetryverification.net,http://portal.tds.net/?inc=4,User-Agent Accept-Language Referer Host,HTTP/1.1,GET /tv2n/vpaid/8bc5b7b,US,oak ridge national laboratory," +	
			"36.02103,-84.25273,US,amazon.com inc.,34.0634,-118.2393,1917.613986";
		
		HTTPDataExtractor httpExtractor = new HTTPDataExtractor(httpInfo);
		STIXPackage stixPackage = httpExtractor.getStixPackage();
		System.out.println("Validating STIX_Package");
		assertTrue(validate(stixPackage));

		Document doc = Jsoup.parse(stixPackage.toXMLString(), "", Parser.xmlParser());

		System.out.println();
		System.out.println("Testing HTTP Request content:");
		Element http = doc.select("HTTPSessionObj|HTTP_Request_Response").first();
		System.out.println("Testing AMP_Version");
		assertEquals(http.select("HTTPSessionObj|Version").text(), "2");
		System.out.println("Testing Request_Len");
		assertEquals(http.select("HTTPSessionObj|Content_Length").text(), "846"); 
		System.out.println("Testing Last_Seen_Timet");
		assertEquals(http.select("HTTPSessionObj|Date").text(), "2015-09-09 00:03:09+00");
		System.out.println("Testing Method");
		assertEquals(http.select("HTTPSessionObj|HTTP_Method").text(), "GET");
		System.out.println("Testing Request");
		assertEquals(http.select("HTTPSessionObj|Value").text(), "/tv2n/vpaid/8bc5b7b");
		System.out.println("Testing Accept_Language");
		assertEquals(http.select("HTTPSessionObj|Accept_Language").text(), "en-US,en;q=0.8");
		System.out.println("Testing User_Agent");
		assertEquals(http.select("HTTPSessionObj|User_Agent").text(), "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36");
		System.out.println("Testing Referer");
		assertEquals(http.select("HTTPSessionObj|Referer").text(), "http://portal.tds.net/?inc=4");
		System.out.println("Testing Full_Data");
		assertEquals(http.select("HTTPSessionObj|Raw_Header").text(), "GET /tv2n/vpaid/8bc5b7b");
		
		System.out.println();
		System.out.println("Testing source IP content:");
		String srcIpId = http.select("HTTPSessionObj|From").attr("object_reference");
		Element srcIp = doc.select("cybox|Observable[id=" + srcIpId + "]").first();
		System.out.println("Testing Title");
		assertEquals(srcIp.select("cybox|Title").text(), "IP");
		System.out.println("Testing Source");
		assertEquals(srcIp.select("cyboxCommon|Information_Source_Type").text(), "HTTPRequest");
		System.out.println("Testing IP Long (ID)");
		assertEquals(srcIp.select("cybox|Object").attr("id"), "stucco:ip-" + ipToLong("128.219.49.13"));
		System.out.println("Testing IP String");
		assertEquals(srcIp.select("AddressObj|Address_Value").text(), "128.219.49.13");
		System.out.println("Testing Description");
		assertEquals(srcIp.select("cybox|Description").text(), "128.219.49.13");
		
		System.out.println();
		System.out.println("Testing DNSName content:");
		String dnsId = http.select("HTTPSessionObj|Domain_Name").attr("object_reference");
		Element dns = doc.select("cybox|Observable[id=" + dnsId + "]").first();
		System.out.println("Testing Name");
		assertEquals(dns.select("DomainNameObj|Value").text(), "cdn455.telemetryverification.net");
		System.out.println("Testing Description");
		assertEquals(dns.select("cybox|description").text(), "cdn455.telemetryverification.net");
		System.out.println("Testing Source");
		assertEquals(dns.select("cyboxcommon|information_source_type").text(), "HTTPRequest");
		System.out.println("Testing Title");
		assertEquals(dns.select("cybox|title").text(), "DNSName");
		
		System.out.println();
		System.out.println("Testing destination IP content:");
		String dstIpId = dns.select("cybox|Related_Object").attr("idref");
		Element dstIp = doc.select("cybox|Observable[id=" + dstIpId + "]").first();
		System.out.println("Testing Title");
		assertEquals(dstIp.select("cybox|Title").text(), "IP");
		System.out.println("Testing Source");
		assertEquals(dstIp.select("cyboxCommon|Information_Source_Type").text(), "HTTPRequest");
		System.out.println("Testing IP Long (ID)");
		assertEquals(dstIp.select("cybox|Object").attr("id"), "stucco:ip-" + ipToLong("54.192.138.232"));
		System.out.println("Testing IP String");
		assertEquals(dstIp.select("AddressObj|Address_Value").text(), "54.192.138.232");
		System.out.println("Testing Description");
		assertEquals(dstIp.select("cybox|Description").text(), "54.192.138.232");

		System.out.println();
		System.out.println("Testing destination Port content:");
		String dstPortId = http.select("HTTPSessionObj|Port").attr("object_reference");
		Element dstPort = doc.select("cybox|Observable[id=" + dstPortId + "]").first();
		System.out.println("Testing Title");
		assertEquals(dstPort.select("cybox|Title").text(), "Port");
		System.out.println("Testing Source");
		assertEquals(dstPort.select("cyboxCommon|Information_Source_Type").text(), "HTTPRequest");
		System.out.println("Testing Port value");
		assertEquals(dstPort.select("PortObj|Port_Value").text(), "80");
		System.out.println("Testing Description");
		assertEquals(dstPort.select("cybox|Description").text(), "80");
	}
}
