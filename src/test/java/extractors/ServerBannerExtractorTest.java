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

import STIXExtractor.ServerBannerExtractor;

/**
 * Unit test for ServerBannerExtractor.
 */
public class ServerBannerExtractorTest extends STIXUtils {
	
	/**
	 * Test empty document
	 */
	@Test
	public void test_empty_doc() {
			
		System.out.println();
		System.out.println("STIXExtractor.ServerBannerExtractor.test_empty_doc()");

		String serverBannerInfo = "";

		ServerBannerExtractor serverBannerExtractor = new ServerBannerExtractor(serverBannerInfo);
		STIXPackage stixPackage = serverBannerExtractor.getStixPackage();

		System.out.println("Testing that STIXPackage is null");
		assertTrue(stixPackage == null);
	}

	/**
	 * Test empty element
	 */
	@Test
	public void test_empty_element() {
			
		System.out.println();
		System.out.println("STIXExtractor.ServerBannerExtractor.test_empty_element()");

		String serverBannerInfo = 
			"filename,recnum,file_type,amp_version,site,banner,addr,app_protocol,times_seen,first_seen_timet,last_seen_timet,countrycode,organization,lat,long\n" +
			",,,,,,,,,,,,,,";

		ServerBannerExtractor serverBannerExtractor = new ServerBannerExtractor(serverBannerInfo);
		STIXPackage stixPackage = serverBannerExtractor.getStixPackage();

		System.out.println("Testing that STIXPackage is null");
		assertTrue(stixPackage == null);
	}
	
	/**
	 * Test empty element with just header
	 */
	@Test
	public void test_empty_element_with_header() {
			
		System.out.println();
		System.out.println("STIXExtractor.ClientBannerExtractor.test_empty_element_with_header()");

		String serverBannerInfo = 
			"filename,recnum,file_type,amp_version,site,banner,addr,app_protocol,times_seen,first_seen_timet,last_seen_timet,countrycode,organization,lat,long";

		ServerBannerExtractor serverBannerExtractor = new ServerBannerExtractor(serverBannerInfo);
		STIXPackage stixPackage = serverBannerExtractor.getStixPackage();

		System.out.println("Testing that STIXPackage is null");
		assertTrue(stixPackage == null);
	}

	/**
	 * Test one element
	 */
	@Test
	public void test_one_element_with_header() {
			
		System.out.println();
		System.out.println("STIXExtractor.ServerBannerExtractor.test_one_element_with_header()");

		String serverBannerInfo = 
			"filename,recnum,file_type,amp_version,site,banner,addr,server_port,app_protocol,times_seen,first_seen_timet,last_seen_timet,countrycode,organization,lat,long\n" +
			"20150817002305-ornl-ampBanS4-1,367,6,2,ornl,Apache,128.219.150.8,80,80,5,2015-08-17 00:14:02+00,2015-08-17 00:14:02+00,US,oak ridge national laboratory,36.02103,-84.25273";

		ServerBannerExtractor serverBannerExtractor = new ServerBannerExtractor(serverBannerInfo);
		STIXPackage stixPackage = serverBannerExtractor.getStixPackage();

		System.out.println("Validating clinet_banner stixPackage");
		assertTrue(serverBannerExtractor.validate(stixPackage));

		Document stixDoc = Jsoup.parse(stixPackage.toXMLString(), "", Parser.xmlParser());		
		Element address = stixDoc.select("cybox|Observable:has(cybox|Title:contains(Address))").first();

		System.out.println();
		System.out.println("Testing Address content:");
		System.out.println("Testing Title");
		assertEquals(address.select("cybox|Title").text(), "Address");
		System.out.println("Testing Source");
		assertEquals(address.select("cyboxCommon|Information_Source_Type").text(), "server_banner");
		System.out.println("Testing Description");
		assertEquals(address.select("cybox|Description").text(), "128.219.150.8, port 80");
		System.out.println("Testing Banner");
		assertEquals(address.select("cyboxCommon|Property[name=Banner]").text(), "Apache");

		System.out.println("Testing Address -> IP reference");
		String ipId = address.select("SocketAddressObj|IP_Address").attr("object_reference");
		Element ip = stixDoc.select("[id= " + ipId + "]").first();

		System.out.println("Testing Address -> Port reference");
		String portId = address.select("SocketAddressObj|Port").attr("object_reference");
		Element port = stixDoc.select("[id= " + portId + "]").first();

		System.out.println();
		System.out.println("Testing IP content:");
		System.out.println("Testing Title");
		assertEquals(ip.select("cybox|Title").text(), "IP");
		System.out.println("Testing Source");
		assertEquals(ip.select("cyboxCommon|Information_Source_Type").text(), "server_banner");
		System.out.println("Testing IP Long (ID)");
		assertEquals(ip.select("cybox|Object").attr("id"), "stucco:ip-" + ipToLong("128.219.150.8"));
		System.out.println("Testing IP String");
		assertEquals(ip.select("AddressObj|Address_Value").text(), "128.219.150.8");
		System.out.println("Testing Description");
		assertEquals(ip.select("cybox|Description").text(), "128.219.150.8");

		System.out.println();
		System.out.println("Testing Port");
		System.out.println("Testing Title");
		assertEquals(port.select("cybox|Title").text(), "Port");
		System.out.println("Testing Source");
		assertEquals(port.select("cyboxCommon|Information_Source_Type").text(), "server_banner");
		System.out.println("Testing Port value");
		assertEquals(port.select("PortObj|Port_Value").text(), "80");
		System.out.println("Testing Description");
		assertEquals(port.select("cybox|Description").text(), "80");
	}
	
	/**
	 * Test three elements
	 */
	@Test
	public void test_three_elements() {
			
		System.out.println();
		System.out.println("STIXExtractor.ServerBannerExtractor.test_three_elements()");

		String serverBannerInfo = 
			"filename,recnum,file_type,amp_version,site,banner,addr,server_port,app_protocol,times_seen,first_seen_timet,last_seen_timet,countrycode,organization,lat,long\n" +
			"20150817002305-ornl-ampBanS4-1,367,6,2,ornl,Apache,128.219.150.8,80,80,5,2015-08-17 00:14:02+00,2015-08-17 00:14:02+00,US,oak ridge national laboratory,36.02103,-84.25273\n" +
			"20150817005305-ornl-ampBanS4-1,5682,6,2,ornl,Apache/2.2.15 (Red Hat),128.219.176.169,80,80,458,2015-08-17 00:38:05+00,2015-08-17 00:38:05+00,US," +
			"oak ridge national laboratory,36.02103,-84.25273\n" +
			"20150817005305-ornl-ampBanS4-1,5759,6,2,ornl,Microsoft-IIS/8.5,128.219.176.173,80,80,5,2015-08-17 00:40:13+00,2015-08-17 00:40:13+00,US,oak ridge national laboratory," +
			"36.02103,-84.25273";

		ServerBannerExtractor serverBannerExtractor = new ServerBannerExtractor(serverBannerInfo);
		STIXPackage stixPackage = serverBannerExtractor.getStixPackage();

		System.out.println("Validating clinet_banner stixPackage");
		assertTrue(serverBannerExtractor.validate(stixPackage));

		Document stixDoc = Jsoup.parse(stixPackage.toXMLString(), "", Parser.xmlParser());		
		Element address = stixDoc.select("cybox|Observable:has(cybox|Description:contains(128.219.150.8, port 80)").first();

		System.out.println();
		System.out.println("Testing Address content:");
		System.out.println("Testing Title");
		assertEquals(address.select("cybox|Title").text(), "Address");
		System.out.println("Testing Source");
		assertEquals(address.select("cyboxCommon|Information_Source_Type").text(), "server_banner");
		System.out.println("Testing Description");
		assertEquals(address.select("cybox|Description").text(), "128.219.150.8, port 80");
		System.out.println("Testing Banner");
		assertEquals(address.select("cyboxCommon|Property[name=Banner]").text(), "Apache");

		System.out.println("Testing Address -> IP reference");
		String ipId = address.select("SocketAddressObj|IP_Address").attr("object_reference");
		Element ip = stixDoc.select("[id= " + ipId + "]").first();

		System.out.println("Testing Address -> Port reference");
		String portId = address.select("SocketAddressObj|Port").attr("object_reference");
		Element port = stixDoc.select("[id= " + portId + "]").first();

		System.out.println();
		System.out.println("Testing IP content:");
		System.out.println("Testing Title");
		assertEquals(ip.select("cybox|Title").text(), "IP");
		System.out.println("Testing Source");
		assertEquals(ip.select("cyboxCommon|Information_Source_Type").text(), "server_banner");
		System.out.println("Testing IP Long (ID)");
		assertEquals(ip.select("cybox|Object").attr("id"), "stucco:ip-" + ipToLong("128.219.150.8"));
		System.out.println("Testing IP String");
		assertEquals(ip.select("AddressObj|Address_Value").text(), "128.219.150.8");
		System.out.println("Testing Description");
		assertEquals(ip.select("cybox|Description").text(), "128.219.150.8");

		System.out.println();
		System.out.println("Testing Port");
		System.out.println("Testing Title");
		assertEquals(port.select("cybox|Title").text(), "Port");
		System.out.println("Testing Source");
		assertEquals(port.select("cyboxCommon|Information_Source_Type").text(), "server_banner");
		System.out.println("Testing Port value");
		assertEquals(port.select("PortObj|Port_Value").text(), "80");
		System.out.println("Testing Description");
		assertEquals(port.select("cybox|Description").text(), "80");

		address = stixDoc.select("cybox|Observable:has(cybox|Description:contains(128.219.176.169, port 80)").first();

		System.out.println();
		System.out.println("Testing Address content:");
		System.out.println("Testing Title");
		assertEquals(address.select("cybox|Title").text(), "Address");
		System.out.println("Testing Source");
		assertEquals(address.select("cyboxCommon|Information_Source_Type").text(), "server_banner");
		System.out.println("Testing Description");
		assertEquals(address.select("cybox|Description").text(), "128.219.176.169, port 80");
		System.out.println("Testing Banner");
		assertEquals(address.select("cyboxCommon|Property[name=Banner]").text(), "Apache/2.2.15 (Red Hat)");

		System.out.println("Testing Address -> IP reference");
		ipId = address.select("SocketAddressObj|IP_Address").attr("object_reference");
		ip = stixDoc.select("[id= " + ipId + "]").first();

		System.out.println("Testing Address -> Port reference");
		portId = address.select("SocketAddressObj|Port").attr("object_reference");
		port = stixDoc.select("[id= " + portId + "]").first();

		System.out.println();
		System.out.println("Testing IP content:");
		System.out.println("Testing Title");
		assertEquals(ip.select("cybox|Title").text(), "IP");
		System.out.println("Testing Source");
		assertEquals(ip.select("cyboxCommon|Information_Source_Type").text(), "server_banner");
		System.out.println("Testing IP Long (ID)");
		assertEquals(ip.select("cybox|Object").attr("id"), "stucco:ip-" + ipToLong("128.219.176.169"));
		System.out.println("Testing IP String");
		assertEquals(ip.select("AddressObj|Address_Value").text(), "128.219.176.169");
		System.out.println("Testing Description");
		assertEquals(ip.select("cybox|Description").text(), "128.219.176.169");

		System.out.println();
		System.out.println("Testing Port");
		System.out.println("Testing Title");
		assertEquals(port.select("cybox|Title").text(), "Port");
		System.out.println("Testing Source");
		assertEquals(port.select("cyboxCommon|Information_Source_Type").text(), "server_banner");
		System.out.println("Testing Port value");
		assertEquals(port.select("PortObj|Port_Value").text(), "80");
		System.out.println("Testing Description");
		assertEquals(port.select("cybox|Description").text(), "80");
		
		address = stixDoc.select("cybox|Observable:has(cybox|Description:contains(28.219.176.173, port 80)").first();

		System.out.println();
		System.out.println("Testing Address content:");
		System.out.println("Testing Title");
		assertEquals(address.select("cybox|Title").text(), "Address");
		System.out.println("Testing Source");
		assertEquals(address.select("cyboxCommon|Information_Source_Type").text(), "server_banner");
		System.out.println("Testing Description");
		assertEquals(address.select("cybox|Description").text(), "128.219.176.173, port 80");
		System.out.println("Testing Banner");
		assertEquals(address.select("cyboxCommon|Property[name=Banner]").text(), "Microsoft-IIS/8.5");

		System.out.println("Testing Address -> IP reference");
		ipId = address.select("SocketAddressObj|IP_Address").attr("object_reference");
		ip = stixDoc.select("[id= " + ipId + "]").first();

		System.out.println("Testing Address -> Port reference");
		portId = address.select("SocketAddressObj|Port").attr("object_reference");
		port = stixDoc.select("[id= " + portId + "]").first();

		System.out.println();
		System.out.println("Testing IP content:");
		System.out.println("Testing Title");
		assertEquals(ip.select("cybox|Title").text(), "IP");
		System.out.println("Testing Source");
		assertEquals(ip.select("cyboxCommon|Information_Source_Type").text(), "server_banner");
		System.out.println("Testing IP Long (ID)");
		assertEquals(ip.select("cybox|Object").attr("id"), "stucco:ip-" + ipToLong("128.219.176.173"));
		System.out.println("Testing IP String");
		assertEquals(ip.select("AddressObj|Address_Value").text(), "128.219.176.173");
		System.out.println("Testing Description");
		assertEquals(ip.select("cybox|Description").text(), "128.219.176.173");

		System.out.println();
		System.out.println("Testing Port");
		System.out.println("Testing Title");
		assertEquals(port.select("cybox|Title").text(), "Port");
		System.out.println("Testing Source");
		assertEquals(port.select("cyboxCommon|Information_Source_Type").text(), "server_banner");
		System.out.println("Testing Port value");
		assertEquals(port.select("PortObj|Port_Value").text(), "80");
		System.out.println("Testing Description");
		assertEquals(port.select("cybox|Description").text(), "80");
	}	
}	
