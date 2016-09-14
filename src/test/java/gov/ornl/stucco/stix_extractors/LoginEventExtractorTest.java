package gov.ornl.stucco.stix_extractors;

import org.jsoup.Jsoup;
import org.jsoup.parser.Parser;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import org.mitre.stix.stix_1.STIXPackage;

import org.xml.sax.SAXException;

import org.junit.Test;

import static org.junit.Assert.*;

/**
 * Unit test for LoginEvent Extractor.
 */
public class LoginEventExtractorTest	{
	
	/**
	 * Test empty document no header
	 */
	@Test
	public void test_empty_document_no_header()	{

		System.out.println("STIXExtractor.LoginEventExtractorTest.test_empty_document()");

		String loginEventInfo = "";

		LoginEventExtractor loginEventExtractor = new LoginEventExtractor(loginEventInfo);
		STIXPackage stixPackage = loginEventExtractor.getStixPackage();
		
		System.out.println("Testing that package is null");
		assertTrue(stixPackage == null);
	}
	
	/**
	 * Test empty document with header
	 */
	@Test
	public void test_empty_document_with_header()	{

		System.out.println("STIXExtractor.LoginEventExtractorTest.test_empty_document()");

		String loginEventInfo = 
			"date_time,hostname,login_software,status,user,from_ip";

		LoginEventExtractor loginEventExtractor = new LoginEventExtractor(loginEventInfo);
		STIXPackage stixPackage = loginEventExtractor.getStixPackage();
		
		System.out.println("Testing that package is null");
		assertTrue(stixPackage == null);
	}

	/**
	 * Test one element with header
	 */
	@Test
	public void test_one_element() throws SAXException {

		System.out.println("STIXExtractor.LoginEventExtractorTest.test_one_element()");

		String loginEventInfo = 
			"Sep 24 15:11:03,StuccoHost,sshd,Accepted,StuccoUser,192.168.10.11";

		LoginEventExtractor loginEventExtractor = new LoginEventExtractor(loginEventInfo);
		STIXPackage stixPackage = loginEventExtractor.getStixPackage();

		System.out.println("Validating LoginEvent stixPackage");
		assertTrue(stixPackage.validate());

		Document doc = Jsoup.parse(stixPackage.toXMLString(), "", Parser.xmlParser());

		System.out.println();
		System.out.println("Testing Hostname:");
		Element hostOne = doc.select("cybox|Observable:has(HostnameObj|Hostname_Value:matches(^StuccoHost\\Z))").first();
		String hostOneID = hostOne.attr("id");
		System.out.println("Testing Name");
		assertEquals(hostOne.select("HostnameObj|Hostname_Value").text(), "StuccoHost");
		System.out.println("Testing Description");
		assertEquals(hostOne.select("cybox|Object > cybox|Description").text(), "StuccoHost");
		System.out.println("Testing Source");
		assertEquals(hostOne.select("cybox|Observable_Source > cyboxCommon|Information_Source_Type").text(), "LoginEvent");
		System.out.println("Testing Title");
		assertEquals(hostOne.select("cybox|Title").text(), "Host");		

		System.out.println();
		System.out.println("Testing Hostname:");
		Element hostTwo = doc.select("cybox|Observable:has(HostnameObj|Hostname_Value:matches(^host_at_192.168.10.11\\Z))").first();
		String hostTwoID = hostTwo.attr("id");
		System.out.println("Testing Name");
		assertEquals(hostTwo.select("HostnameObj|Hostname_Value").text(), "host_at_192.168.10.11");
		System.out.println("Testing Description");
		assertEquals(hostTwo.select("cybox|Object > cybox|Description").text(), "host_at_192.168.10.11");
		System.out.println("Testing Source");
		assertEquals(hostTwo.select("cybox|Observable_Source > cyboxCommon|Information_Source_Type").text(), "LoginEvent");
		System.out.println("Testing Title");
		assertEquals(hostTwo.select("cybox|Title").text(), "Host");

		System.out.println();
		System.out.println("Testing Software:");
		Element sshSoftware = doc.select("cybox|Observable:has(cybox|Title:matches(^Software\\Z))").first();
		String sshSoftwareID = sshSoftware.attr("id");
		System.out.println("Testing Name");
		assertEquals(sshSoftware.select("ProductObj|Product").text(), "sshd");
		System.out.println("Testing Description");
		assertEquals(sshSoftware.select("cybox|Description").text(), "sshd");
		System.out.println("Testing Source");
		assertEquals(sshSoftware.select("cyboxCommon|Information_Source_Type").text(), "LoginEvent");
		System.out.println("Testing Title");
		assertEquals(sshSoftware.select("cybox|Title").text(), "Software");

		System.out.println();
		System.out.println("Testing IP:");
		Element ip = doc.select("cybox|Observable:has(cybox|Title:matches(^IP\\Z))").first();
		String ipID = ip.attr("id");
		System.out.println("Testing Name");
		assertEquals(ip.select("AddressObj|Address_Value").text(), "192.168.10.11");
		System.out.println("Testing Description");
		assertEquals(ip.select("cybox|Description").text(), "192.168.10.11");
		System.out.println("Testing Source");
		assertEquals(ip.select("cyboxCommon|Information_Source_Type").text(), "LoginEvent");
		System.out.println("Testing Title");
		assertEquals(ip.select("cybox|Title").text(), "IP");

		System.out.println("Testing Hostname -> Software relation");
		Element softwareReference = hostOne.select("cybox|Object > cybox|Related_Objects > cybox|Related_Object[idref = " + sshSoftwareID + "]").first();
		assertNotNull(softwareReference);

		System.out.println("Testing Hostname_at_IP -> IP relation");
		Element ipReference = hostTwo.select("cybox|Object > cybox|Related_Objects > cybox|Related_Object[idref = " + ipID + "]").first();
		assertNotNull(ipReference);

		System.out.println();
		System.out.println("Testing Account:");
		Element account = doc.select("cybox|Observable:has(cybox|Title:matches(^Account\\Z))").first();
		System.out.println("Testing Name");
		assertEquals(account.select("UserAccountObj|Username").text(), "StuccoUser");
		System.out.println("Testing Description");
		assertEquals(account.select("AccountObj|Description").text(), "StuccoUser");
		System.out.println("Testing Source");
		assertEquals(account.select("cybox|Observable_Source > cyboxCommon|Information_Source_Type").text(), "LoginEvent");
		System.out.println("Testing Title");
		assertEquals(account.select("cybox|Title").text(), "Account");

		System.out.println("Testing Account -> Hostname relation");
		Element hostReference = account.select("cybox|Object > cybox|Related_Objects > cybox|Related_Object[idref = " + hostOneID + "]").first();
		assertNotNull(hostReference);

		System.out.println("Testing Account -> Hostname_at_IP relation");
		hostReference = account.select("cybox|Object > cybox|Related_Objects > cybox|Related_Object[idref = " + hostTwoID + "]").first();
		assertNotNull(hostReference);
	}
}
