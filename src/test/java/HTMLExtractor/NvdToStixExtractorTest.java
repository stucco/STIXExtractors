package STIXExtractor;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.Map;

import org.jsoup.Jsoup;
import org.jsoup.parser.Parser;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Test;

import org.mitre.stix.stix_1.STIXPackage;
import org.mitre.stix.common_1.ExploitTargetsType;
import org.mitre.stix.exploittarget_1.ExploitTarget;
import org.mitre.stix.exploittarget_1.VulnerabilityType;
						
import static org.junit.Assert.*;

/**
 * Unit test for simple App.
 */			
public class NvdToStixExtractorTest {
	
	/**
	 * Tests empty doc
	 */
	@Test
	public void test_empty_doc()	{

		System.out.println("STIXExtractor.NvdToStixExtractorTest.test_empty_doc()");
			
		String nvdInfo = "";
		
		NvdToStixExtractor nvdExt = new NvdToStixExtractor(nvdInfo);
		STIXPackage stixPackage = nvdExt.getStixPackage();
		
		System.out.println("Testing that StixPackage is null");
		assertTrue(stixPackage == null);
	}
	
	/**
	 * Tests doc with empty entry
	 */
	@Test
	public void test_empty_entry()	{

		System.out.println("STIXExtractor.NvdToStixExtractorTest.test_empty_entry()");
			
		String nvdInfo = 
			" <?xml version='1.0' encoding='UTF-8'?> " +
			"    <nvd xmlns:scap-core=\"http://scap.nist.gov/schema/scap-core/0.1\" xmlns=\"http://scap.nist.gov/schema/feed/vulnerability/2.0\" xmlns:cpe-lang=\"http://cpe.mitre.org/language/2.0\" xmlns:cvss=\"http://scap.nist.gov/schema/cvss-v2/0.2\" xmlns:patch=\"http://scap.nist.gov/schema/patch/0.1\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:vuln=\"http://scap.nist.gov/schema/vulnerability/0.4\" nvd_xml_version=\"2.0\" pub_date=\"2013-07-22T10:00:00\" xsi:schemaLocation=\"http://scap.nist.gov/schema/patch/0.1 http://nvd.nist.gov/schema/patch_0.1.xsd http://scap.nist.gov/schema/scap-core/0.1 http://nvd.nist.gov/schema/scap-core_0.1.xsd http://scap.nist.gov/schema/feed/vulnerability/2.0 http://nvd.nist.gov/schema/nvd-cve-feed_2.0.xsd\"> " +
			"      <entry id=\"\"> " +
			"      </entry> ";
		
		NvdToStixExtractor nvdExt = new NvdToStixExtractor(nvdInfo);
		STIXPackage stixPackage = nvdExt.getStixPackage();
		
		System.out.println("Testing that StixPackage is null");
		assertTrue(stixPackage == null);
	}
	
	/**
	 * Tests nvd with just one entry
	 */
	@Test
	public void test_one_entry()	{

		System.out.println("STIXExtractor.NvdToStixExtractorTest.test_one_entry()");
			
		String nvdInfo =
			" <?xml version='1.0' encoding='UTF-8'?> " +
			"    <nvd xmlns:scap-core=\"http://scap.nist.gov/schema/scap-core/0.1\" xmlns=\"http://scap.nist.gov/schema/feed/vulnerability/2.0\" xmlns:cpe-lang=\"http://cpe.mitre.org/language/2.0\" xmlns:cvss=\"http://scap.nist.gov/schema/cvss-v2/0.2\" xmlns:patch=\"http://scap.nist.gov/schema/patch/0.1\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:vuln=\"http://scap.nist.gov/schema/vulnerability/0.4\" nvd_xml_version=\"2.0\" pub_date=\"2013-07-22T10:00:00\" xsi:schemaLocation=\"http://scap.nist.gov/schema/patch/0.1 http://nvd.nist.gov/schema/patch_0.1.xsd http://scap.nist.gov/schema/scap-core/0.1 http://nvd.nist.gov/schema/scap-core_0.1.xsd http://scap.nist.gov/schema/feed/vulnerability/2.0 http://nvd.nist.gov/schema/nvd-cve-feed_2.0.xsd\"> " +
			"      <entry id=\"CVE-2013-2361\"> " +
			"        <vuln:cve-id>CVE-2013-2361</vuln:cve-id> " +
			"        <vuln:published-datetime>2013-07-22T07:19:36.253-04:00</vuln:published-datetime> " +
			"        <vuln:last-modified-datetime>2013-07-22T07:19:36.253-04:00</vuln:last-modified-datetime> " +
			"        <vuln:references xml:lang=\"en\" reference_type=\"UNKNOWN\"> " +
			"          <vuln:source>HP</vuln:source> " +
			"          <vuln:reference href=\"https://h20564.www2.hp.com/portal/site/hpsc/public/kb/docDisplay?docId=emr_na-c03839862\" xml:lang=\"en\">HPSBMU02900</vuln:reference> " +
			"        </vuln:references> " +
			"        <vuln:references xml:lang=\"en\" reference_type=\"UNKNOWN\"> " +
			"          <vuln:source>SOURCE</vuln:source> " +
			"          <vuln:reference xml:lang=\"en\">description</vuln:reference> " +
			"        </vuln:references> " +
			"        <vuln:vulnerable-software-list> " +
			"          <vuln:product>cpe:/a:HP:System_Management_Homepage:7.2.0</vuln:product> " +
			"        </vuln:vulnerable-software-list> " +
			" " +
			"        <vuln:summary>Cross-site scripting (XSS) vulnerability in HP System Management Homepage (SMH) before 7.2.1 allows remote attackers to inject arbitrary web script or HTML via unspecified vectors.</vuln:summary> " +
			"      </entry> " +
			"    </nvd> ";

		NvdToStixExtractor nvdExt = new NvdToStixExtractor(nvdInfo);
		STIXPackage stixPackage = nvdExt.getStixPackage();
		
		System.out.println("Validating StixPackage");
		assertTrue(nvdExt.validate(stixPackage));

		Document stix = Jsoup.parse(stixPackage.toXMLString(), "", Parser.xmlParser());

		Document doc = Jsoup.parse(nvdInfo);
		Elements entries = doc.select("entry");

		for (Element entry : entries) {
			System.out.println();
			Element stixEntry = stix.select("stixCommon|Exploit_Target:has(et|CVE_ID:matches(^" + entry.attr("id") + "$))").first();
			System.out.println("Testing ID");
			assertEquals(stixEntry.select("et|CVE_ID").text(), entry.attr("id"));
			System.out.println("Testing Title");
			assertEquals(stixEntry.select("et|Title").text(), "Vulnerability");
			System.out.println("Testing Source");
			assertEquals(stixEntry.select("et|Source").text(), "NVD");
			System.out.println("Testing Description");
			assertEquals(stixEntry.select("et|Description").text(), entry.select("vuln|summary").text());
			System.out.println("Testing References");
			Elements refs = entry.select("vuln|references");
			for (Element ref : refs) {
				String content = (ref.select("vuln|reference").first().attr("href").isEmpty()) 
					? ref.select("vuln|source").text() + ":" + ref.select("vuln|reference").text() 
					: ref.select("vuln|reference").first().attr("href");
				assertTrue(!stixEntry.select("stixCommon|Reference:contains(" + content + ")").first().text().isEmpty());
			}
			System.out.println("Testing PublishedDate");
			assertEquals(stixEntry.select("et|Published_DateTime").text(), entry.select("vuln|published-datetime").text());
			System.out.println("Testing CVSSScore");
			assertEquals(stixEntry.select("et|Base_Score").text(), entry.select("cvss|score").text());

			System.out.println("Testing AffectedSoftware");
			Elements infoSws = entry.select("vuln|product");
			Elements stixSws = stixEntry.select("et|Affected_Software > et|Affected_Software > stixCommon|Observable");
			assertEquals(infoSws.size(), stixSws.size());
			for (Element infoSw : infoSws) {
				boolean found = false;
				for (Element stixSw : stixSws) {
					String id = stixSw.attr("idref");
					Element foundSw = stix.select("cybox|Observable[id=" + id + "]").first();
					found = (foundSw.select("ProductObj|Product").first().text().equals(infoSw.text())) ? true : false;
					if (found) {
						break;
					}
				}
				if (found) {
					assertTrue(found);
				} else {
					System.out.println("ERROR: Could not find " + infoSw.text());
					assertTrue(found);
				}
			}
		}
	}
	
	/**
	 * Tests nvd with two entries
	 */
	@Test
	public void test_two_entries()	{
			
		System.out.println("STIXExtractor.NvdToStixExtractorTest.test_two_entries()");
		
		String nvdInfo =
			" <?xml version='1.0' encoding='UTF-8'?> " +
			"    <nvd xmlns:scap-core=\"http://scap.nist.gov/schema/scap-core/0.1\" xmlns=\"http://scap.nist.gov/schema/feed/vulnerability/2.0\" xmlns:cpe-lang=\"http://cpe.mitre.org/language/2.0\" xmlns:cvss=\"http://scap.nist.gov/schema/cvss-v2/0.2\" xmlns:patch=\"http://scap.nist.gov/schema/patch/0.1\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:vuln=\"http://scap.nist.gov/schema/vulnerability/0.4\" nvd_xml_version=\"2.0\" pub_date=\"2013-07-22T10:00:00\" xsi:schemaLocation=\"http://scap.nist.gov/schema/patch/0.1 http://nvd.nist.gov/schema/patch_0.1.xsd http://scap.nist.gov/schema/scap-core/0.1 http://nvd.nist.gov/schema/scap-core_0.1.xsd http://scap.nist.gov/schema/feed/vulnerability/2.0 http://nvd.nist.gov/schema/nvd-cve-feed_2.0.xsd\"> " +
			" " +
			"      <entry id=\"CVE-2013-4878\"> " +
			" " +
			"        <vuln:vulnerable-configuration id=\"http://nvd.nist.gov/\"> " +
			"          <cpe-lang:logical-test negate=\"false\" operator=\"AND\"> " +
			"            <cpe-lang:logical-test negate=\"false\" operator=\"OR\"> " +
			"              <cpe-lang:fact-ref name=\"cpe:/a:parallels:parallels_plesk_panel:9.2\"/> " +
			"              <cpe-lang:fact-ref name=\"cpe:/a:parallels:parallels_plesk_panel:9.0\"/> " +
			"              <cpe-lang:fact-ref name=\"cpe:/a:parallels:parallels_small_business_panel:10.0\"/> " +
			"            </cpe-lang:logical-test> " +
			"            <cpe-lang:logical-test negate=\"false\" operator=\"OR\"> " +
			"              <cpe-lang:fact-ref name=\"cpe:/o:linux:linux_kernel\"/> " +
			"            </cpe-lang:logical-test> " +
			"          </cpe-lang:logical-test> " +
			"        </vuln:vulnerable-configuration> " +
			" " +
			"        <vuln:cve-id>CVE-2013-4878</vuln:cve-id> " +
			" " +
			"        <vuln:published-datetime>2013-07-18T12:51:56.227-04:00</vuln:published-datetime> " +
			"        <vuln:last-modified-datetime>2013-07-19T16:51:21.577-04:00</vuln:last-modified-datetime> " +
			"        <vuln:cvss> " +
			"          <cvss:base_metrics> " +
			"            <cvss:score>6.8</cvss:score> " +
			"            <cvss:access-vector>NETWORK</cvss:access-vector> " +
			"            <cvss:access-complexity>MEDIUM</cvss:access-complexity> " +
			"            <cvss:authentication>NONE</cvss:authentication> " +
			"            <cvss:confidentiality-impact>PARTIAL</cvss:confidentiality-impact> " +
			"            <cvss:integrity-impact>PARTIAL</cvss:integrity-impact> " +
			"            <cvss:availability-impact>PARTIAL</cvss:availability-impact> " +
			"            <cvss:source>http://nvd.nist.gov</cvss:source> " +
			"            <cvss:generated-on-datetime>2013-07-19T16:37:00.000-04:00</cvss:generated-on-datetime> " +
			"          </cvss:base_metrics> " +
			"        </vuln:cvss> " +
			"        <vuln:cwe id=\"CWE-264\"/> " +
			"        <vuln:summary>The default configuration of Parallels Plesk Panel 9.0.x and 9.2.x on UNIX, and Small Business Panel 10.x on UNIX, has an improper ScriptAlias directive for phppath, which makes it easier for remote attackers to execute arbitrary code via a crafted request, a different vulnerability than CVE-2012-1823.</vuln:summary> " +
			"      </entry> " +
			"      <entry id=\"CVE-2013-5217\"> " +
			"        <vuln:cve-id>CVE-2013-5217</vuln:cve-id> " +
			"        <vuln:published-datetime>2013-07-22T07:20:46.637-04:00</vuln:published-datetime> " +
			"        <vuln:last-modified-datetime>2013-07-22T07:20:47.053-04:00</vuln:last-modified-datetime> " +
			"        <vuln:summary>** REJECT **  DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: CVE-2012-5217.  Reason: This candidate is a duplicate of CVE-2012-5217.  A typo caused the wrong ID to be used.  Notes: All CVE users should reference CVE-2012-5217 instead of this candidate.  All references and descriptions in this candidate have been removed to prevent accidental usage.</vuln:summary> " +
			"      </entry> ";

		NvdToStixExtractor nvdExt = new NvdToStixExtractor(nvdInfo);
		STIXPackage stixPackage = nvdExt.getStixPackage();

		System.out.println("Validating StixPackage");
		assertTrue(nvdExt.validate(stixPackage));

		Document stix = Jsoup.parse(stixPackage.toXMLString(), "", Parser.xmlParser());

		Document doc = Jsoup.parse(nvdInfo);
		Elements entries = doc.select("entry");

		for (Element entry : entries) {
			System.out.println();
			Element stixEntry = stix.select("stixCommon|Exploit_Target:has(et|CVE_ID:matches(^" + entry.attr("id") + "$))").first();
			System.out.println("Testing ID");
			assertEquals(stixEntry.select("et|CVE_ID").text(), entry.attr("id"));
			System.out.println("Testing Title");
			assertEquals(stixEntry.select("et|Title").text(), "Vulnerability");
			System.out.println("Testing Source");
			assertEquals(stixEntry.select("et|Source").text(), "NVD");
			System.out.println("Testing Description");
			assertEquals(stixEntry.select("et|Description").text(), entry.select("vuln|summary").text());
			System.out.println("Testing References");
			Elements refs = entry.select("vuln|references");
			for (Element ref : refs) {
				String content = (ref.select("vuln|reference").first().attr("href").isEmpty()) 
					? ref.select("vuln|source").text() + ":" + ref.select("vuln|reference").text() 
					: ref.select("vuln|reference").first().attr("href");
				assertTrue(!stixEntry.select("stixCommon|Reference:contains(" + content + ")").first().text().isEmpty());
			}
			System.out.println("Testing PublishedDate");
			assertEquals(stixEntry.select("et|Published_DateTime").text(), entry.select("vuln|published-datetime").text());
			System.out.println("Testing CVSSScore");
			assertEquals(stixEntry.select("et|Base_Score").text(), entry.select("cvss|score").text());

			System.out.println("Testing AffectedSoftware");
			Elements infoSws = entry.select("vuln|product");
			Elements stixSws = stixEntry.select("et|Affected_Software > et|Affected_Software > stixCommon|Observable");
			assertEquals(infoSws.size(), stixSws.size());
			for (Element infoSw : infoSws) {
				boolean found = false;
				for (Element stixSw : stixSws) {
					String id = stixSw.attr("idref");
					Element foundSw = stix.select("cybox|Observable[id=" + id + "]").first();
					found = (foundSw.select("ProductObj|Product").first().text().equals(infoSw.text())) ? true : false;
					if (found) {
						break;
					}
				}
				if (found) {
					assertTrue(found);
				} else {
					System.out.println("ERROR: Could not find " + infoSw.text());
					assertTrue(found);
				}
			}
		}
	}		

	/**
	 * Tests nvd with tree entries
	 */
	@Test
	public void test_three_entries()	{
		
		System.out.println("STIXExtractor.NvdToStixExtractorTest.test_three_entries()");
			
		String nvdInfo = 
			"<?xml version='1.0' encoding='UTF-8'?> " +
			"    <nvd xmlns:scap-core=\"http://scap.nist.gov/schema/scap-core/0.1\" xmlns=\"http://scap.nist.gov/schema/feed/vulnerability/2.0\" xmlns:cpe-lang=\"http://cpe.mitre.org/language/2.0\" xmlns:cvss=\"http://scap.nist.gov/schema/cvss-v2/0.2\" xmlns:patch=\"http://scap.nist.gov/schema/patch/0.1\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:vuln=\"http://scap.nist.gov/schema/vulnerability/0.4\" nvd_xml_version=\"2.0\" pub_date=\"2013-07-22T10:00:00\" xsi:schemaLocation=\"http://scap.nist.gov/schema/patch/0.1 http://nvd.nist.gov/schema/patch_0.1.xsd http://scap.nist.gov/schema/scap-core/0.1 http://nvd.nist.gov/schema/scap-core_0.1.xsd http://scap.nist.gov/schema/feed/vulnerability/2.0 http://nvd.nist.gov/schema/nvd-cve-feed_2.0.xsd\"> " +
			" " +
			"      <entry id=\"CVE-2099-0001\"> " +
			"      </entry> " +
			" " +
			"      <entry id=\"CVE-2099-0002\"> " +
			"        <vuln:vulnerable-software-list> " +
			"          <vuln:product>cpe:/a:parallels:parallels_plesk_panel:9.2</vuln:product> " +
			"        </vuln:vulnerable-software-list> " +
			"      </entry> " +
			" " +
			"      <entry id=\"CVE-2099-0003\"> " +
			"        <vuln:vulnerable-software-list> " +
			"          <vuln:product>cpe:/a:parallels:parallels_small_business_panel:10.0</vuln:product> " +
			"          <vuln:product>cpe:/a:parallels:parallels_plesk_panel:9.0</vuln:product> " +
			"          <vuln:product>cpe:/a:parallels:parallels_plesk_panel:9.2</vuln:product> " +
			"        </vuln:vulnerable-software-list> " +
			"      </entry> ";

		NvdToStixExtractor nvdExt = new NvdToStixExtractor(nvdInfo);
		STIXPackage stixPackage = nvdExt.getStixPackage();

		System.out.println("Validating StixPackage");
		assertTrue(nvdExt.validate(stixPackage));

		Document stix = Jsoup.parse(stixPackage.toXMLString(), "", Parser.xmlParser());

		Document doc = Jsoup.parse(nvdInfo);
		Elements entries = doc.select("entry");

		for (Element entry : entries) {
			System.out.println();
			Element stixEntry = stix.select("stixCommon|Exploit_Target:has(et|CVE_ID:matches(^" + entry.attr("id") + "$))").first();
			System.out.println("Testing ID");
			assertEquals(stixEntry.select("et|CVE_ID").text(), entry.attr("id"));
			System.out.println("Testing Title");
			assertEquals(stixEntry.select("et|Title").text(), "Vulnerability");
			System.out.println("Testing Source");
			assertEquals(stixEntry.select("et|Source").text(), "NVD");
			System.out.println("Testing Description");
			assertEquals(stixEntry.select("et|Description").text(), entry.select("vuln|summary").text());
			System.out.println("Testing References");
			Elements refs = entry.select("vuln|references");
			for (Element ref : refs) {
				String content = (ref.select("vuln|reference").first().attr("href").isEmpty()) 
					? ref.select("vuln|source").text() + ":" + ref.select("vuln|reference").text() 
					: ref.select("vuln|reference").first().attr("href");
				assertTrue(!stixEntry.select("stixCommon|Reference:contains(" + content + ")").first().text().isEmpty());
			}
			System.out.println("Testing PublishedDate");
			assertEquals(stixEntry.select("et|Published_DateTime").text(), entry.select("vuln|published-datetime").text());
			System.out.println("Testing CVSSScore");
			assertEquals(stixEntry.select("et|Base_Score").text(), entry.select("cvss|score").text());

			System.out.println("Testing AffectedSoftware");
				Elements infoSws = entry.select("vuln|product");
				Elements stixSws = stixEntry.select("et|Affected_Software > et|Affected_Software > stixCommon|Observable");
				assertEquals(infoSws.size(), stixSws.size());
				for (Element infoSw : infoSws) {
					boolean found = false;
					for (Element stixSw : stixSws) {
						String id = stixSw.attr("idref");
						Element foundSw = stix.select("cybox|Observable[id=" + id + "]").first();
						found = (foundSw.select("ProductObj|Product").first().text().equals(infoSw.text())) ? true : false;
						if (found) {
							break;
						}
					}
					if (found) {
						assertTrue(found);
					} else {
						System.out.println("ERROR: Could not find " + infoSw.text());
						assertTrue(found);
					}
				}
		}

	}
}
