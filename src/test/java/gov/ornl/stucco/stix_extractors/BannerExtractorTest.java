package gov.ornl.stucco.stix_extractors;

import gov.ornl.stucco.utils.STIXUtils;

import java.util.List;

import java.io.IOException;

import org.apache.commons.csv.CSVRecord;

import org.jsoup.parser.Parser;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import org.mitre.stix.stix_1.STIXPackage;

import org.xml.sax.SAXException;

import org.junit.Test;

import static org.junit.Assert.*;

/**
 * Unit test for BannerExtractor.
 */
public class BannerExtractorTest extends STIXUtils {
	
	/**
	 * Test empty document
	 */
	@Test
	public void test_empty_doc() {
			
		System.out.println();
		System.out.println("STIXExtractor.BannerExtractor.test_empty_doc()");

		String bannerInfo = "";

		BannerExtractor bannerExtractor = new BannerExtractor(bannerInfo);
		STIXPackage stixPackage = bannerExtractor.getStixPackage();

		System.out.println("Testing that STIXPackage is null");
		assertTrue(stixPackage == null);
	}

	/**
	 * Test empty element
	 */
	@Test
	public void test_empty_element() {
			
		System.out.println();
		System.out.println("STIXExtractor.BannerExtractor.test_empty_element()");

		String bannerInfo = 
			"filename,recnum,file_type,amp_version,site,banner,addr,app_protocol,times_seen,first_seen,last_seen,cc,org,lat,lon\n" +
			",,,,,,,,,,,,,,";

		BannerExtractor bannerExtractor = new BannerExtractor(bannerInfo);
		STIXPackage stixPackage = bannerExtractor.getStixPackage();

		System.out.println("Testing that STIXPackage is null");
		assertTrue(stixPackage == null);
	}
	
	/**
	 * Test empty element with just header
	 */
	@Test
	public void test_empty_element_with_header() {
			
		System.out.println();
		System.out.println("STIXExtractor.BannerExtractor.test_empty_element_with_header()");

		String bannerInfo = 
			"filename,recnum,file_type,amp_version,site,banner,addr,app_protocol,times_seen,first_seen,last_seen,cc,org,lat,lon";

		BannerExtractor bannerExtractor = new BannerExtractor(bannerInfo);
		STIXPackage stixPackage = bannerExtractor.getStixPackage();

		System.out.println("Testing that STIXPackage is null");
		assertTrue(stixPackage == null);
	}

	/**
	 * Test one element
	 */
	@Test
	public void test_one_element_with_header() throws SAXException {
			
		System.out.println();
		System.out.println("STIXExtractor.BannerExtractor.test_one_element_with_header()");

		String bannerInfo = 
			"filename,recnum,file_type,amp_version,site,banner,addr,server_port,app_protocol,times_seen,first_seen,last_seen,cc,org,lat,lon\n" +
			"20160803152157-site-ampBanS4-1.dat,32474,6,2,site,Apache,64.90.41.213,80,80,20,2016-08-03 15:06:58,2016-08-03 15:06:58,US,new dream network llc,33.91787,-117.89075";

		BannerExtractor bannerExtractor = new BannerExtractor(bannerInfo);
		STIXPackage stixPackage = bannerExtractor.getStixPackage();

		System.out.println("Validating clinet_banner stixPackage");
		assertTrue(stixPackage.validate());

		Document stixDoc = Jsoup.parse(stixPackage.toXMLString(), "", Parser.xmlParser());		
		Element address = stixDoc.select("cybox|Observable:has(cybox|Title:contains(Address))").first();

		System.out.println();
		System.out.println("Testing Address content:");
		System.out.println("Testing Title");
		assertEquals(address.select("cybox|Title").text(), "Address");
		System.out.println("Testing Source");
		assertEquals(address.select("cyboxCommon|Information_Source_Type").text(), "banner");
		System.out.println("Testing Description");
		assertEquals(address.select("cybox|Description").text(), "64.90.41.213, port 80");
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
		assertEquals(ip.select("cyboxCommon|Information_Source_Type").text(), "banner");
		System.out.println("Testing IP Long (ID)");
		assertEquals(ip.select("cybox|Object").attr("id"), "stucco:ip-" + ipToLong("64.90.41.213"));
		System.out.println("Testing IP String");
		assertEquals(ip.select("AddressObj|Address_Value").text(), "64.90.41.213");
		System.out.println("Testing Description");
		assertEquals(ip.select("cybox|Description").text(), "64.90.41.213");

		System.out.println();
		System.out.println("Testing Port");
		System.out.println("Testing Title");
		assertEquals(port.select("cybox|Title").text(), "Port");
		System.out.println("Testing Source");
		assertEquals(port.select("cyboxCommon|Information_Source_Type").text(), "banner");
		System.out.println("Testing Port value");
		assertEquals(port.select("PortObj|Port_Value").text(), "80");
		System.out.println("Testing Description");
		assertEquals(port.select("cybox|Description").text(), "80");
	}
}	
