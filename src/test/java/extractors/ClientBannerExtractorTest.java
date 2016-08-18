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

import STIXExtractor.ClientBannerExtractor;

/**
 * Unit test for ClientBannerExtractor.
 */
public class ClientBannerExtractorTest extends STIXUtils {
	
	/**
	 * Test empty document
	 */
	@Test
	public void test_empty_doc() {
			
		System.out.println();
		System.out.println("STIXExtractor.ClientBannerExtractor.test_empty_doc()");

		String clientBannerInfo = "";

		ClientBannerExtractor clientBannerExtractor = new ClientBannerExtractor(clientBannerInfo);
		STIXPackage stixPackage = clientBannerExtractor.getStixPackage();

		System.out.println("Testing that STIXPackage is null");
		assertTrue(stixPackage == null);
	}

	/**
	 * Test empty element
	 */
	@Test
	public void test_empty_element() {
			
		System.out.println();
		System.out.println("STIXExtractor.ClientBannerExtractor.test_empty_element()");

		String clientBannerInfo = 
			"filename,recnum,file_type,amp_version,site,banner,addr,app_protocol,times_seen,first_seen_timet,last_seen_timet,countrycode,organization,lat,long\n" +
			",,,,,,,,,,,,,,";

		ClientBannerExtractor clientBannerExtractor = new ClientBannerExtractor(clientBannerInfo);
		STIXPackage stixPackage = clientBannerExtractor.getStixPackage();

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

		String clientBannerInfo = 
			"filename,recnum,file_type,amp_version,site,banner,addr,app_protocol,times_seen,first_seen_timet,last_seen_timet,countrycode,organization,lat,long";

		ClientBannerExtractor clientBannerExtractor = new ClientBannerExtractor(clientBannerInfo);
		STIXPackage stixPackage = clientBannerExtractor.getStixPackage();

		System.out.println("Testing that STIXPackage is null");
		assertTrue(stixPackage == null);
	}

	/**
	 * Test one element
	 */
	@Test
	public void test_one_element_with_header() {
			
		System.out.println();
		System.out.println("STIXExtractor.ClientBannerExtractor.test_one_element_with_header()");

		String clientBannerInfo = 
			"filename,recnum,file_type,amp_version,site,banner,addr,app_protocol,times_seen,first_seen_timet,last_seen_timet,countrycode,organization,lat,long\n" +
			"20150817000957-ornl-ampBanC4-1,1680,5,2,ornl,Entrust Entelligence Security Provider,160.91.155.43,80,1,2015-08-17 00:04:49+00," +
			"2015-08-17 00:04:49+00,US,oak ridge national laboratory,36.02103,-84.25273";		

		ClientBannerExtractor clientBannerExtractor = new ClientBannerExtractor(clientBannerInfo);
		STIXPackage stixPackage = clientBannerExtractor.getStixPackage();

		System.out.println("Validating clinet_banner stixPackage");
		assertTrue(clientBannerExtractor.validate(stixPackage));

		Document stixDoc = Jsoup.parse(stixPackage.toXMLString(), "", Parser.xmlParser());		
		Element address = stixDoc.select("cybox|Observable:has(cybox|Title:contains(Address))").first();

		System.out.println();
		System.out.println("Testing Address content:");
		System.out.println("Testing Title");
		assertEquals(address.select("cybox|Title").text(), "Address");
		System.out.println("Testing Source");
		assertEquals(address.select("cyboxCommon|Information_Source_Type").text(), "client_banner");
		System.out.println("Testing Description");
		assertEquals(address.select("cybox|Description").text(), "160.91.155.43, port 80");
		System.out.println("Testing Banner");
		assertEquals(address.select("cyboxCommon|Property[name=Banner]").text(), "Entrust Entelligence Security Provider");

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
		assertEquals(ip.select("cyboxCommon|Information_Source_Type").text(), "client_banner");
		System.out.println("Testing IP Long (ID)");
		assertEquals(ip.select("cybox|Object").attr("id"), "stucco:ip-" + ipToLong("160.91.155.43"));
		System.out.println("Testing IP String");
		assertEquals(ip.select("AddressObj|Address_Value").text(), "160.91.155.43");
		System.out.println("Testing Description");
		assertEquals(ip.select("cybox|Description").text(), "160.91.155.43");

		System.out.println();
		System.out.println("Testing Port");
		System.out.println("Testing Title");
		assertEquals(port.select("cybox|Title").text(), "Port");
		System.out.println("Testing Source");
		assertEquals(port.select("cyboxCommon|Information_Source_Type").text(), "client_banner");
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
		System.out.println("STIXExtractor.ClientBannerExtractor.test_three_elements()");

		String clientBannerInfo = 
			"filename,recnum,file_type,amp_version,site,banner,addr,app_protocol,times_seen,first_seen_timet,last_seen_timet,countrycode,organization,lat,long\n" +
			"20150817000957-ornl-ampBanC4-1,1680,5,2,ornl,Entrust Entelligence Security Provider,160.91.155.43,80,1,2015-08-17 00:04:49+00,2015-08-17 00:04:49+00," +
			"US,oak ridge national laboratory,36.02103,-84.25273\n" +
			"20150817000957-ornl-ampBanC4-1,4414,5,2,ornl,Entrust Entelligence Security Provider,160.91.218.146,80,5,2015-08-17 00:00:00+00,2015-08-17 00:00:00+00," +
			"US,oak ridge national laboratory,36.02103,-84.25273\n" +
			"20150817000957-ornl-ampBanC4-1,395,5,2,ornl,iTunes/12.2.1 (Macintosh; OS X 10.9.5) AppleWebKit/537.78.2,128.219.49.13,80,2,2015-08-17 00:08:58+00," +
			"2015-08-17 00:08:58+00,US,oak ridge national laboratory,36.02103,-84.25273";

		ClientBannerExtractor clientBannerExtractor = new ClientBannerExtractor(clientBannerInfo);
		STIXPackage stixPackage = clientBannerExtractor.getStixPackage();

		System.out.println("Validating clinet_banner stixPackage");
		assertTrue(clientBannerExtractor.validate(stixPackage));

		Document stixDoc = Jsoup.parse(stixPackage.toXMLString(), "", Parser.xmlParser());		
		Element address = stixDoc.select("cybox|Observable:has(cybox|Description:contains(160.91.155.43, port 80)").first();

		System.out.println();
		System.out.println("Testing Address content:");
		System.out.println("Testing Title");
		assertEquals(address.select("cybox|Title").text(), "Address");
		System.out.println("Testing Source");
		assertEquals(address.select("cyboxCommon|Information_Source_Type").text(), "client_banner");
		System.out.println("Testing Description");
		assertEquals(address.select("cybox|Description").text(), "160.91.155.43, port 80");
		System.out.println("Testing Banner");
		assertEquals(address.select("cyboxCommon|Property[name=Banner]").text(), "Entrust Entelligence Security Provider");

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
		assertEquals(ip.select("cyboxCommon|Information_Source_Type").text(), "client_banner");
		System.out.println("Testing IP Long (ID)");
		assertEquals(ip.select("cybox|Object").attr("id"), "stucco:ip-" + ipToLong("160.91.155.43"));
		System.out.println("Testing IP String");
		assertEquals(ip.select("AddressObj|Address_Value").text(), "160.91.155.43");
		System.out.println("Testing Description");
		assertEquals(ip.select("cybox|Description").text(), "160.91.155.43");

		System.out.println();
		System.out.println("Testing Port");
		System.out.println("Testing Title");
		assertEquals(port.select("cybox|Title").text(), "Port");
		System.out.println("Testing Source");
		assertEquals(port.select("cyboxCommon|Information_Source_Type").text(), "client_banner");
		System.out.println("Testing Port value");
		assertEquals(port.select("PortObj|Port_Value").text(), "80");
		System.out.println("Testing Description");
		assertEquals(port.select("cybox|Description").text(), "80");

		address = stixDoc.select("cybox|Observable:has(cybox|Description:contains(160.91.218.146, port 80)").first();

		System.out.println();
		System.out.println("Testing Address content:");
		System.out.println("Testing Title");
		assertEquals(address.select("cybox|Title").text(), "Address");
		System.out.println("Testing Source");
		assertEquals(address.select("cyboxCommon|Information_Source_Type").text(), "client_banner");
		System.out.println("Testing Description");
		assertEquals(address.select("cybox|Description").text(), "160.91.218.146, port 80");
		System.out.println("Testing Banner");
		assertEquals(address.select("cyboxCommon|Property[name=Banner]").text(), "Entrust Entelligence Security Provider");

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
		assertEquals(ip.select("cyboxCommon|Information_Source_Type").text(), "client_banner");
		System.out.println("Testing IP Long (ID)");
		assertEquals(ip.select("cybox|Object").attr("id"), "stucco:ip-" + ipToLong("160.91.218.146"));
		System.out.println("Testing IP String");
		assertEquals(ip.select("AddressObj|Address_Value").text(), "160.91.218.146");
		System.out.println("Testing Description");
		assertEquals(ip.select("cybox|Description").text(), "160.91.218.146");

		System.out.println();
		System.out.println("Testing Port");
		System.out.println("Testing Title");
		assertEquals(port.select("cybox|Title").text(), "Port");
		System.out.println("Testing Source");
		assertEquals(port.select("cyboxCommon|Information_Source_Type").text(), "client_banner");
		System.out.println("Testing Port value");
		assertEquals(port.select("PortObj|Port_Value").text(), "80");
		System.out.println("Testing Description");
		assertEquals(port.select("cybox|Description").text(), "80");
		
		address = stixDoc.select("cybox|Observable:has(cybox|Description:contains(128.219.49.13, port 80)").first();

		System.out.println();
		System.out.println("Testing Address content:");
		System.out.println("Testing Title");
		assertEquals(address.select("cybox|Title").text(), "Address");
		System.out.println("Testing Source");
		assertEquals(address.select("cyboxCommon|Information_Source_Type").text(), "client_banner");
		System.out.println("Testing Description");
		assertEquals(address.select("cybox|Description").text(), "128.219.49.13, port 80");
		System.out.println("Testing Banner");
		assertEquals(address.select("cyboxCommon|Property[name=Banner]").text(), "iTunes/12.2.1 (Macintosh; OS X 10.9.5) AppleWebKit/537.78.2");

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
		assertEquals(ip.select("cyboxCommon|Information_Source_Type").text(), "client_banner");
		System.out.println("Testing IP Long (ID)");
		assertEquals(ip.select("cybox|Object").attr("id"), "stucco:ip-" + ipToLong("128.219.49.13"));
		System.out.println("Testing IP String");
		assertEquals(ip.select("AddressObj|Address_Value").text(), "128.219.49.13");
		System.out.println("Testing Description");
		assertEquals(ip.select("cybox|Description").text(), "128.219.49.13");

		System.out.println();
		System.out.println("Testing Port");
		System.out.println("Testing Title");
		assertEquals(port.select("cybox|Title").text(), "Port");
		System.out.println("Testing Source");
		assertEquals(port.select("cyboxCommon|Information_Source_Type").text(), "client_banner");
		System.out.println("Testing Port value");
		assertEquals(port.select("PortObj|Port_Value").text(), "80");
		System.out.println("Testing Description");
		assertEquals(port.select("cybox|Description").text(), "80");
	}	
}	
