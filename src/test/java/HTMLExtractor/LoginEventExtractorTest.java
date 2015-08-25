package STIXExtractor;

import org.jsoup.Jsoup;
import org.jsoup.parser.Parser;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import org.mitre.stix.stix_1.STIXPackage;

import org.junit.Test;

import static org.junit.Assert.*;

import STIXExtractor.LoginEventExtractor;

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
	public void test_one_element()	{

		System.out.println("STIXExtractor.LoginEventExtractorTest.test_one_element()");

		String loginEventInfo = 
			"Sep 24 15:11:03,StuccoHost,sshd,Accepted,StuccoUser,192.168.10.11";

		LoginEventExtractor loginEventExtractor = new LoginEventExtractor(loginEventInfo);
		STIXPackage stixPackage = loginEventExtractor.getStixPackage();

		System.out.println("Validating LoginEvent stixPackage");
		loginEventExtractor.validate(stixPackage);

		Document doc = Jsoup.parse(stixPackage.toXMLString(), "", Parser.xmlParser());
		Element element = doc.select("cybox|Observable:has(HostnameObj|Hostname_Value:matches(^StuccoHost\\Z))").first();

		System.out.println();
		System.out.println("Testing Hostname:");
		System.out.println("Testing Name");
		assertEquals(element.select("HostnameObj|Hostname_Value").text(), "StuccoHost");
		System.out.println("Testing Description");
		assertEquals(element.select("cybox|Object > cybox|Description").text(), "StuccoHost");
		System.out.println("Testing Source");
		assertEquals(element.select("cybox|Observable_Source > cyboxCommon|Information_Source_Type").text(), "LoginEvent");
		System.out.println("Testing Title");
		assertEquals(element.select("cybox|Title").text(), "Host");
		System.out.println("Testing Hostname -> Software relation");
		String softwareId = element.select("cybox|Related_Object:has(cybox|Relationship:matches(^runs\\Z))").attr("idref");
		Element software = doc.select("[id=" + softwareId + "]").first();
		assertEquals(software.select("ProductObj|Product").text(), "sshd");
		
		element = doc.select("cybox|Observable:has(HostnameObj|Hostname_Value:matches(^host_at_192.168.10.11\\Z))").first();

		System.out.println();
		System.out.println("Testing Hostname:");
		System.out.println("Testing Name");
		assertEquals(element.select("HostnameObj|Hostname_Value").text(), "host_at_192.168.10.11");
		System.out.println("Testing Description");
		assertEquals(element.select("cybox|Object > cybox|Description").text(), "host_at_192.168.10.11");
		System.out.println("Testing Source");
		assertEquals(element.select("cybox|Observable_Source > cyboxCommon|Information_Source_Type").text(), "LoginEvent");
		System.out.println("Testing Title");
		assertEquals(element.select("cybox|Title").text(), "Host");
		System.out.println("Testing Hostname_at_IP -> IP relation");
		String ipId = element.select("cybox|Related_Object:has(cybox|Relationship:matches(^hasIP\\Z))").attr("idref");
		Element ip = doc.select("[id=" + ipId + "]").first();
		assertEquals(ip.select("AddressObj|Address_Value").text(), "192.168.10.11");
		
		element = doc.select("cybox|Observable:has(cybox|Title:matches(^Account\\Z))").first();

		System.out.println();
		System.out.println("Testing Account:");
		System.out.println("Testing Name");
		assertEquals(element.select("UserAccountObj|Username").text(), "StuccoUser");
		System.out.println("Testing Description");
		assertEquals(element.select("AccountObj|Description").text(), "StuccoUser");
		System.out.println("Testing Source");
		assertEquals(element.select("cybox|Observable_Source > cyboxCommon|Information_Source_Type").text(), "LoginEvent");
		System.out.println("Testing Title");
		assertEquals(element.select("cybox|Title").text(), "Account");
		System.out.println("Testing Account -> Hostname relation");
		String hostnameId = element.select("cybox|Related_Object:has(cybox|Description:matches(^StuccoUser logs in to StuccoHost\\Z))").attr("idref");
		Element host = doc.select("[id=" + hostnameId + "]").first();
		assertEquals(host.select("HostnameObj|Hostname_Value").text(), "StuccoHost");
		System.out.println("Testing Account -> Hostname_at_IP relation");
		hostnameId = element.select("cybox|Related_Object:has(cybox|Description:matches(^StuccoUser logs in from host at 192.168.10.11\\Z))").attr("idref");
		host = doc.select("[id=" + hostnameId + "]").first();
		assertEquals(host.select("HostnameObj|Hostname_Value").text(), "host_at_192.168.10.11");
		
		element = doc.select("cybox|Observable:has(cybox|Title:matches(^Software\\Z))").first();

		System.out.println();
		System.out.println("Testing Software:");
		System.out.println("Testing Name");
		assertEquals(element.select("ProductObj|Product").text(), "sshd");
		System.out.println("Testing Description");
		assertEquals(element.select("cybox|Description").text(), "sshd");
		System.out.println("Testing Source");
		assertEquals(element.select("cyboxCommon|Information_Source_Type").text(), "LoginEvent");
		System.out.println("Testing Title");
		assertEquals(element.select("cybox|Title").text(), "Software");
		
		element = doc.select("cybox|Observable:has(cybox|Title:matches(^IP\\Z))").first();

		System.out.println();
		System.out.println("Testing IP:");
		System.out.println("Testing Name");
		assertEquals(element.select("AddressObj|Address_Value").text(), "192.168.10.11");
		System.out.println("Testing Description");
		assertEquals(element.select("cybox|Description").text(), "192.168.10.11");
		System.out.println("Testing Source");
		assertEquals(element.select("cyboxCommon|Information_Source_Type").text(), "LoginEvent");
		System.out.println("Testing Title");
		assertEquals(element.select("cybox|Title").text(), "IP");
	}
}
