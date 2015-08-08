package STIXExtractor;

import org.jsoup.Jsoup;
import org.jsoup.parser.Parser;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import org.mitre.stix.stix_1.STIXPackage;

import org.junit.Test;

import static org.junit.Assert.*;

import STIXExtractor.GeoIPExtractor;

/**
 * Unit test for Metasploit Extractor.
 */
public class MetasploitExtractorTest	{
	
	/**
	 * Test empty document no header
	 */
	@Test
	public void test_empty_document_no_header()	{

		System.out.println("STIXExtractor.GeoIPExtractorTest.test_empty_document_no_header()");

		String metasploitInfo = "";

		MetasploitExtractor metasploitExtractor = new MetasploitExtractor(metasploitInfo);
		STIXPackage stixPackage = metasploitExtractor.getStixPackage();

		System.out.println("Testing that package is null");
		assertTrue(stixPackage == null);
	}
	
	/**
	 * Test empty document with header
	 */
	@Test
	public void test_empty_document_with_header()	{

		System.out.println("STIXExtractor.GeoIPExtractorTest.test_empty_document_with_hader()");

		String metasploitInfo = "";

		MetasploitExtractor metasploitExtractor = new MetasploitExtractor(metasploitInfo);
		STIXPackage stixPackage = metasploitExtractor.getStixPackage();

		System.out.println("Testing that package is null");
		assertTrue(stixPackage == null);
	}
	
	/**
	 * Test one Metasploit element
	 */
	@Test
	public void test_one_element_no_cve()	{

		System.out.println("STIXExtractor.GeoIPExtractorTest.test_one_element_no_cve()");

		String metasploitInfo = 
			"\"id\",\"mtime\",\"file\",\"mtype\",\"refname\",\"fullname\",\"name\",\"rank\",\"description\",\"license\",\"privileged\"," +
			"\"disclosure_date\",\"default_target\",\"default_action\",\"stance\",\"ready\",\"ref_names\",\"author_names\" \n" +
			"-1,,,,,-1,,,,,,,,,,,,";

		MetasploitExtractor metasploitExtractor = new MetasploitExtractor(metasploitInfo);
		STIXPackage stixPackage = metasploitExtractor.getStixPackage();
		
		System.out.println("Validating Metasploit stixPackage");
		assertTrue(metasploitExtractor.validate(stixPackage));

		Document doc = Jsoup.parse(stixPackage.toXMLString(), "", Parser.xmlParser());
		Element element = doc.select("stix|TTP").first();
	
		System.out.println("Testing Malware (Exploit) content:");

		System.out.println("Testing Title");		
		assertEquals(element.select("ttp|Behavior > ttp|Exploits > ttp|Exploit > ttp|Title").text(), "-1");

		System.out.println("Testing Description");		
		assertEquals(element.select("ttp|Description").text(), "");

		System.out.println("Testing ShortDescription");		
		assertEquals(element.select("ttp|Short_Description").text(), "");

		System.out.println("Testing Source");		
		assertEquals(element.select("stixCommon|Name").text(), "Metasploit");

		System.out.println("Testing Malware (Exploit) -> Vulnerability relation");		
		assertEquals(element.select("stixCommon|Exploit_Target").attr("idref"), doc.select("stix|Exploit_Targets > stixCommon|Exploit_Target").attr("id"));
	}
	
	/**
	 * Test one Metasploit element with cve
	 */
	@Test
	public void test_one_element_with_cve()	{

		System.out.println("STIXExtractor.GeoIPExtractorTest.test_one_element_with_cve()");

		String metasploitInfo = 
			"\"id\",\"mtime\",\"file\",\"mtype\",\"refname\",\"fullname\",\"name\",\"rank\",\"description\",\"license\",\"privileged\"," +
			"\"disclosure_date\",\"default_target\",\"default_action\",\"stance\",\"ready\",\"ref_names\",\"author_names\"\n" +
			"1,\"2013-05-07 00:25:41\",\"/opt/metasploit/apps/pro/msf3/modules/exploits/aix/rpc_cmsd_opcode21.rb\",\"exploit\"," +
			"\"aix/rpc_cmsd_opcode21\",\"exploit/aix/rpc_cmsd_opcode21\"," +
			"\"AIX Calendar Manager Service Daemon (rpc.cmsd) Opcode 21 Buffer Overflow\",500,\"This module exploits a buffer overflow vulnerability " +
			"in opcode 21 handled by rpc.cmsd on AIX. By making a request with a long string passed to the first argument of " +
			"the \"\"rtable_create\"\" RPC, a stack based buffer overflow occurs. This leads to arbitrary code execution.  NOTE: " +
			"Unsuccessful attempts may cause inetd/portmapper to enter a state where further attempts are not possible.\"," +
			"\"Metasploit Framework License (BSD)\",\"f\",\"2009-10-07 00:00:00\",0,,\"aggressive\",\"t\"," +
			"\"BID-36615, CVE-2009-3699, OSVDB-58726, URL-http://aix.software.ibm.com/aix/efixes/security/cmsd_advisory.asc, " +
			"URL-http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=825\"," +
			"\"Rodrigo Rubira Branco (BSDaemon), jduck <jduck@metasploit.com>\"";
		
		MetasploitExtractor metasploitExtractor = new MetasploitExtractor(metasploitInfo);
		STIXPackage stixPackage = metasploitExtractor.getStixPackage();

		System.out.println("Validating Metasploit stixPackage");
		assertTrue(metasploitExtractor.validate(stixPackage));

		Document doc = Jsoup.parse(stixPackage.toXMLString(), "", Parser.xmlParser());
		Element element = doc.select("stix|TTP").first();
	
		System.out.println("Testing Malware (Exploit) content:");

		System.out.println("Testing Title");		
		assertEquals(element.select("ttp|Behavior > ttp|Exploits > ttp|Exploit > ttp|Title").text(), "exploit/aix/rpc_cmsd_opcode21");

		System.out.println("Testing Description");		
		assertEquals(element.select("ttp|Description").text(), "This module exploits a buffer overflow vulnerability in opcode 21 handled by rpc.cmsd on AIX. By making a request with a long string passed to the first argument of the \"rtable_create\" RPC, a stack based buffer overflow occurs. This leads to arbitrary code execution. NOTE: Unsuccessful attempts may cause inetd/portmapper to enter a state where further attempts are not possible.");

		System.out.println("Testing ShortDescription");		
		assertEquals(element.select("ttp|Short_Description").text(), "AIX Calendar Manager Service Daemon (rpc.cmsd) Opcode 21 Buffer Overflow");

		System.out.println("Testing Source");		
		assertEquals(element.select("stixCommon|Name").text(), "Metasploit");

		System.out.println("Testing Malware (Exploit) -> Vulnerability relation");		
		assertEquals(element.select("stixCommon|Exploit_Target").attr("idref"), doc.select("stix|Exploit_Targets > stixCommon|Exploit_Target").attr("id"));

		System.out.println("Testing Vulnerability content:");

		element = doc.select("stix|Exploit_Targets > stixCommon|Exploit_Target").first();
		assertEquals(element.select("et|Vulnerability > et|Title").text(), "CVE-2009-3699");

		System.out.println("Testing Description");		
		assertEquals(element.select("et|Description").text(), "CVE-2009-3699");
		
		System.out.println("Testing Id");		
		assertEquals(element.select("et|CVE_ID").text(), "CVE-2009-3699");

		System.out.println("Testing Source");		
		assertEquals(element.select("et|Source").text(), "Metasploit");
	}

	/**
	 * Test one Metasploit element with two cve
	 */
	@Test
	public void test_one_element_with_two_cve()	{

		System.out.println("STIXExtractor.GeoIPExtractorTest.test_one_element_with_two_cve()");

		String metasploitInfo = 
			"\"id\",\"mtime\",\"file\",\"mtype\",\"refname\",\"fullname\",\"name\",\"rank\",\"description\",\"license\",\"privileged\"," +
			"\"disclosure_date\",\"default_target\",\"default_action\",\"stance\",\"ready\",\"ref_names\",\"author_names\"\n" +
			"1,\"2013-05-07 00:25:41\",\"/opt/metasploit/apps/pro/msf3/modules/exploits/aix/rpc_cmsd_opcode21.rb\",\"exploit\"," +
			"\"aix/rpc_cmsd_opcode21\",\"exploit/aix/rpc_cmsd_opcode21\",\"AIX Calendar Manager Service Daemon (rpc.cmsd) Opcode 21 Buffer Overflow\"," +
			"500,\"This module exploits a buffer overflow vulnerability in opcode 21 handled by rpc.cmsd on AIX. By making a request with a long " +
			"string passed to the first argument of the \"\"rtable_create\"\" RPC, a stack based buffer overflow occurs. This leads to arbitrary code " +
			"execution.  NOTE: Unsuccessful attempts may cause inetd/portmapper to enter a state where further attempts are not possible.\"," +
			"\"Metasploit Framework License (BSD)\",\"f\",\"2009-10-07 00:00:00\",0,,\"aggressive\",\"t\",\"BID-36615, CVE-2009-3699, CVE-2009-3456, " +
			"OSVDB-58726, URL-http://aix.software.ibm.com/aix/efixes/security/cmsd_advisory.asc, " +
			"URL-http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=825\",\"Rodrigo Rubira Branco (BSDaemon), jduck <jduck@metasploit.com>\"";		

		MetasploitExtractor metasploitExtractor = new MetasploitExtractor(metasploitInfo);
		STIXPackage stixPackage = metasploitExtractor.getStixPackage();

		System.out.println("Validating Metasploit stixPackage");
		assertTrue(metasploitExtractor.validate(stixPackage));

		Document doc = Jsoup.parse(stixPackage.toXMLString(), "", Parser.xmlParser());
		Element element = doc.select("stix|TTP").first();
	
		System.out.println("Testing Malware (Exploit) content:");

		System.out.println("Testing Title");		
		assertEquals(element.select("ttp|Behavior > ttp|Exploits > ttp|Exploit > ttp|Title").text(), "exploit/aix/rpc_cmsd_opcode21");

		System.out.println("Testing Description");		
		assertEquals(element.select("ttp|Description").text(), "This module exploits a buffer overflow vulnerability in opcode 21 handled by rpc.cmsd on AIX. By making a request with a long string passed to the first argument of the \"rtable_create\" RPC, a stack based buffer overflow occurs. This leads to arbitrary code execution. NOTE: Unsuccessful attempts may cause inetd/portmapper to enter a state where further attempts are not possible.");

		System.out.println("Testing ShortDescription");		
		assertEquals(element.select("ttp|Short_Description").text(), "AIX Calendar Manager Service Daemon (rpc.cmsd) Opcode 21 Buffer Overflow");

		System.out.println("Testing Source");		
		assertEquals(element.select("stixCommon|Name").text(), "Metasploit");

		System.out.println("Testing Malware (Exploit) -> Vulnerability relation");	
		Elements idrefs = element.select("stixCommon|Exploit_Target");
		
		for (Element idref : idrefs)		
			assertEquals(element.select("stixCommon|Exploit_Target").attr("idref"), doc.select("stix|Exploit_Targets > stixCommon|Exploit_Target").attr("id"));
		

		System.out.println("Testing Vulnerability content:");
		System.out.println("Testing 1st CVE:");

		element = doc.select("stix|Exploit_Targets > stixCommon|Exploit_Target:has(et|CVE_ID:contains(CVE-2009-3699)").first();
		assertEquals(element.select("et|Vulnerability > et|Title").text(), "CVE-2009-3699");

		System.out.println("Testing Description");		
		assertEquals(element.select("et|Description").text(), "CVE-2009-3699");
		
		System.out.println("Testing Id");		
		assertEquals(element.select("et|CVE_ID").text(), "CVE-2009-3699");

		System.out.println("Testing Source");		
		assertEquals(element.select("et|Source").text(), "Metasploit");
		
		System.out.println("Testing 2nd CVE:");

		element = doc.select("stix|Exploit_Targets > stixCommon|Exploit_Target:has(et|CVE_ID:contains(CVE-2009-3456)").first();
		assertEquals(element.select("et|Vulnerability > et|Title").text(), "CVE-2009-3456");

		System.out.println("Testing Description");		
		assertEquals(element.select("et|Description").text(), "CVE-2009-3456");
		
		System.out.println("Testing Id");		
		assertEquals(element.select("et|CVE_ID").text(), "CVE-2009-3456");

		System.out.println("Testing Source");		
		assertEquals(element.select("et|Source").text(), "Metasploit");
	}
}
