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
 * Unit test for CVE Extractor.
 */
public class CveExtractorTest {
	
	/**
	 * Test empty doc
	 */
	@Test
	public void test_empty_doc() {

		System.out.println();
		System.out.println("STIXExtractor.CveExtractorTest.test_empty_doc()");
		String cveInfo = "";
		
		CveExtractor cveExtractor = new CveExtractor(cveInfo);
		STIXPackage stixPackage = cveExtractor.getStixPackage();
		
		assertTrue(stixPackage == null);
	}

	/**
	 * Test one element
	 */
	@Test
	public void test_one_element() throws SAXException {

		System.out.println();
		System.out.println("STIXExtractor.CveExtractorTest.test_one_element()");
		String cveInfo =
			"http://www.w3.org/2001/XMLSchema-instance\" " +
			"           xmlns=\"http://cve.mitre.org/cve/downloads\" " +
			"           xsi:noNamespaceSchemaLocation=\"http://cve.mitre.org/schema/cve/cve_1.0.xsd\"> " +
			"        <item type=\"CAN\" name=\"CVE-1999-0001\" seq=\"1999-0001\"> " +
			"        <status>Candidate</status> " +
			"        <phase date=\"20051217\">Modified</phase> " +
			"        <desc>ip_input.c in BSD-derived TCP/IP implementations allows remote attackers to cause a denial of service (crash or hang) via crafted packets.</desc> " +
			"        <refs> " +
			"        <ref source=\"CERT\">CA-98-13-tcp-denial-of-service</ref> " +
			"        </refs> " +
			"        <votes> " +
			"        <modify count=\"1\">Frech</modify> " +
			"        <noop count=\"2\">Northcutt, Wall</noop> " +
			"        <reviewing count=\"1\">Christey</reviewing> " +
			"        </votes> " +
			"        <comments> " +
			"        <comment voter=\"Christey\">A Bugtraq posting indicates that the bug has to do with " +
			"        &quot;short packets with certain options set,&quot; so the description " +
			"        should be modified accordingly. " +
			"        But is this the same as CVE-1999-0052?  That one is related " +
			"        to nestea (CVE-1999-0257) and probably the one described in " +
			"        BUGTRAQ:19981023 nestea v2 against freebsd 3.0-Release " +
			"        The patch for nestea is in ip_input.c around line 750. " +
			"        The patches for CVE-1999-0001 are in lines 388&amp;446.  So,  " +
			"        CVE-1999-0001 is different from CVE-1999-0257 and CVE-1999-0052. " +
			"        The FreeBSD patch for CVE-1999-0052 is in line 750. " +
			"        So, CVE-1999-0257 and CVE-1999-0052 may be the same, though " +
			"        CVE-1999-0052 should be RECAST since this bug affects Linux " +
			"        and other OSes besides FreeBSD.</comment> " +
			"        <comment voter=\"Frech\">XF:teardrop(338) " +
			"        This assignment was based solely on references to the CERT advisory.</comment> " +
			"        <comment voter=\"Christey\">The description for BID:190, which links to CVE-1999-0052 (a " +
			"        FreeBSD advisory), notes that the patches provided by FreeBSD in " +
			"        CERT:CA-1998-13 suggest a connection between CVE-1999-0001 and " +
			"        CVE-1999-0052.  CERT:CA-1998-13 is too vague to be sure without " +
			"        further analysis.</comment> " +
			"        </comments> " +
			"        </item> " +
			"      </cve> ";

		CveExtractor cveExtractor = new CveExtractor(cveInfo);
		STIXPackage stixPackage = cveExtractor.getStixPackage();

		System.out.println("Validating CVE stixPackage");
		assertTrue(stixPackage.validate());

		System.out.println("Testing one element CVE content");
		Document doc = Jsoup.parse(stixPackage.toXMLString(), "", Parser.xmlParser());
		Elements elements = doc.select("stixCommon|Exploit_Target");
			
		System.out.println("Testing that package contains one element");					
		assertTrue(elements.size() == 1);

		for (Element element : elements)	{
			System.out.println("Testing CVE_ID");
			assertEquals(element.select("et|CVE_ID").text(), "CVE-1999-0001");
			
			System.out.println("Testing Title");
			assertEquals(element.select("et|Title").text(), "Vulnerability");
			
			System.out.println("Testing Source");
			assertEquals(element.select("et|Source").text(), "CVE");
			
			System.out.println("Testing Description");
			assertEquals(element.select("et|Description").text(), "ip_input.c in BSD-derived TCP/IP implementations allows remote attackers to cause a denial of service (crash or hang) via crafted packets.");
			
			System.out.println("Testing ShortDescription (comments)");
			boolean equals = true;
			Elements comments = element.select("et|Short_Description");
			for (Element comment : comments)	{
				if (comment.text().equals(
				"A Bugtraq posting indicates that the bug has to do with \"short packets " +
				"with certain options set,\" so the description should be modified accordingly. " +
				"But is this the same as CVE-1999-0052? That one is related to nestea (CVE-1999-0257) " + 
				"and probably the one described in BUGTRAQ:19981023 nestea v2 against freebsd " +
				"3.0-Release The patch for nestea is in ip_input.c around line 750. The patches for " +
				"CVE-1999-0001 are in lines 388&446. So, CVE-1999-0001 is different from CVE-1999-0257 " +
				"and CVE-1999-0052. The FreeBSD patch for CVE-1999-0052 is in line 750. So, CVE-1999-0257 " +
				"and CVE-1999-0052 may be the same, though CVE-1999-0052 should be RECAST since this bug " +
				"affects Linux and other OSes besides FreeBSD.") ||
				 comment.text().equals(
				 "The description for BID:190, which links to CVE-1999-0052 (a " +
				 "FreeBSD advisory), notes that the patches provided by FreeBSD in " +
				 "CERT:CA-1998-13 suggest a connection between CVE-1999-0001 and " +
				 "CVE-1999-0052. CERT:CA-1998-13 is too vague to be sure without " +
				 "further analysis.") ||
				 comment.text().equals(
				 "XF:teardrop(338) " +
				 "This assignment was based solely on references to the CERT advisory.")) 
					continue;
				else 	{
					System.out.println("ERROR: Cannot find comment: " + comment.text());
					equals = false;
				}
			}
			assertTrue(equals);

			System.out.println("Testing References");
			assertEquals(element.select("stixCommon|Reference").text(), "CERT:CA-98-13-tcp-denial-of-service");
			
			System.out.println("Testing IsPubliclyAcknowledged (status)");
			assertEquals(element.select("et|Vulnerability").attr("is_publicly_acknowledged"), "false");
		}
	}
	
	/**
	 * Test two elements
	 */
	@Test
	public void test_two_elements()	throws SAXException {

		System.out.println();
		System.out.println("STIXExtractor.CveExtractorTest.test_two_elements()");
		String cveInfo =
			"      <?xml version=\"1.0\"?> " +
			"      <cve xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" " +
			"           xmlns=\"http://cve.mitre.org/cve/downloads\" " +
			"           xsi:noNamespaceSchemaLocation=\"http://cve.mitre.org/schema/cve/cve_1.0.xsd\"> " +
			"        <item type=\"CVE\" name=\"CVE-1999-0002\" seq=\"1999-0002\"> " +
			"        <status>Entry</status> " +
			"        <desc>Buffer overflow in NFS mountd gives root access to remote attackers, mostly in Linux systems.</desc> " +
			"        <refs> " +
			"        <ref source=\"SGI\" url=\"ftp://patches.sgi.com/support/free/security/advisories/19981006-01-I\">19981006-01-I</ref> " +
			"        <ref source=\"CERT\">CA-98.12.mountd</ref> " +
			"        <ref source=\"CIAC\" url=\"http://www.ciac.org/ciac/bulletins/j-006.shtml\">J-006</ref> " +
			"        <ref source=\"BID\" url=\"http://www.securityfocus.com/bid/121\">121</ref> " +
			"        <ref source=\"XF\">linux-mountd-bo</ref> " +
			"        </refs> " +
			"        </item> " +
			"        <item type=\"CAN\" name=\"CVE-2011-0528\" seq=\"2011-0528\"> " +
			"        <status>Candidate</status> " +
			"        <phase date=\"20110120\">Assigned</phase> " +
			"        <desc>** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem.  When the candidate has been publicized, the details for this candidate will be provided.</desc> " +
			"        <refs> " +
			"        </refs> " +
			"        <votes> " +
			"        </votes> " +
			"        <comments> " +
			"        </comments> " +
			"        </item> " +
			"      </cve> ";

		CveExtractor cveExtractor = new CveExtractor(cveInfo);
		STIXPackage stixPackage = cveExtractor.getStixPackage();

		System.out.println("Validating CVE stixPackage");
		assertTrue(stixPackage.validate());

		System.out.println("Testing two elements CVE content");
		
		Document doc = Jsoup.parse(stixPackage.toXMLString(), "", Parser.xmlParser());
		Elements elements = doc.select("stixCommon|Exploit_Target");
								
		System.out.println("Testing that package contains two elements");					
		assertTrue(elements.size() == 2);

		int count = 0;
		for (Element element : elements) {
		
			if (count == 0)	{
				System.out.println();
				System.out.println("Testing first element:");
				count++;
			} else {
				System.out.println();
				System.out.println("Testing second element:");
			}
			if (element.attr("id").equals("stucco:cve-CVE-1999-0002"))	{
				System.out.println("Testing CVE_ID");
				assertEquals(element.select("et|CVE_ID").text(), "CVE-1999-0002");
				
				System.out.println("Testing Title");
				assertEquals(element.select("et|Title").text(), "Vulnerability");
				
				System.out.println("Testing Source");
				assertEquals(element.select("et|Source").text(), "CVE");
				
				System.out.println("Testing Description");
				assertEquals(element.select("et|Description").text(), "Buffer overflow in NFS mountd gives root access to remote attackers, mostly in Linux systems.");
				
				System.out.println("Testing References");
				boolean equals = true;
				Elements references = element.select("stixCommon|Reference");
				for (Element reference : references) {
					reference.text();
					if (reference.text().equals("ftp://patches.sgi.com/support/free/security/advisories/19981006-01-I") ||
						reference.text().equals("CERT:CA-98.12.mountd") ||
						reference.text().equals("http://www.ciac.org/ciac/bulletins/j-006.shtml") ||
						reference.text().equals("http://www.securityfocus.com/bid/121") ||
						reference.text().equals("XF:linux-mountd-bo")) continue;
					else  	{
						System.out.println("ERROR: Cannot find: " + reference.text());
						equals = false;
					}
				}
				assertTrue(equals);
			
				System.out.println("Testing IsPubliclyAcknowledged (status)");
				assertEquals(element.select("et|Vulnerability").attr("is_publicly_acknowledged"), "true"); 
			}
			if (element.attr("id").equals("stucco:cve-CVE-2011-0528")) {
				System.out.println("Testing CVE_ID");
				assertEquals(element.select("et|CVE_ID").text(), "CVE-2011-0528");
				
				System.out.println("Testing Title");
				assertEquals(element.select("et|Title").text(), "Vulnerability");
				
				System.out.println("Testing Source");
				assertEquals(element.select("et|Source").text(), "CVE");
				
				System.out.println("Testing Description");
				assertEquals(element.select("et|Description").text(), "** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.");
				
				System.out.println("Testing IsPubliclyAcknowledged (status)");
				assertEquals(element.select("et|Vulnerability").attr("is_publicly_acknowledged"), "false"); 
			}
		
		
		}
		
	}
}
