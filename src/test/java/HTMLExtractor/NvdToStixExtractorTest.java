package STIXExtractor;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.Map;

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
	 * Tests nvd with just one entry
	 */
	@Test
	public void test_one_entry()	{
			
		try {
			File nvdFile = new File("./testData/nvd/nvdcve-2.0-2002_pt1.xml");
			Charset charset = Charset.defaultCharset();
			String nvdInfo = FileUtils.readFileToString(nvdFile, charset);

			nvdInfo =
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

			String expectedVerts =
				"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " +
				"<stix:STIX_Package id=\"stucco:NVD-bde50930-f00e-473c-9942-52a48bdf6402\" " +
				"    timestamp=\"2015-07-27T21:22:42.319Z\" " +
				"    xmlns=\"http://xml/metadataSharing.xsd\" " +
				"    xmlns:ProductObj=\"http://cybox.mitre.org/objects#ProductObject-2\" " +
				"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" " +
				"    xmlns:cyboxCommon=\"http://cybox.mitre.org/common-2\" " +
				"    xmlns:et=\"http://stix.mitre.org/ExploitTarget-1\" " +
				"    xmlns:indicator=\"http://stix.mitre.org/Indicator-2\" " +
				"    xmlns:stix=\"http://stix.mitre.org/stix-1\" " +
				"    xmlns:stixCommon=\"http://stix.mitre.org/common-1\" xmlns:stucco=\"gov.ornl.stucco\"> " +
				"    <stix:STIX_Header> " +
				"        <stix:Title>NVD</stix:Title> " +
				"    </stix:STIX_Header> " +
				"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\"> " +
				"        <cybox:Observable id=\"stucco:software-b73ef432-7f6a-4fb7-b5ca-b4406c42e632\"> " +
				"            <cybox:Title>Software</cybox:Title> " +
				"            <cybox:Observable_Source name=\"NVD\"> " +
				"                <cyboxCommon:Information_Source_Type>National Vulnerability Database</cyboxCommon:Information_Source_Type> " +
				"            </cybox:Observable_Source> " +
				"            <cybox:Object> " +
				"                <cybox:Description>HP System_Management_Homepage version 7.2.0</cybox:Description> " +
				"                <cybox:Properties " +
				"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"ProductObj:ProductObjectType\"> " +
				"                    <ProductObj:Product>cpe:/a:HP:System_Management_Homepage:7.2.0</ProductObj:Product> " +
				"                </cybox:Properties> " +
				"            </cybox:Object> " +
				"        </cybox:Observable> " +
				"    </stix:Observables> " +
				"    <stix:Indicators> " +
				"        <stix:Indicator " +
				"            id=\"stucco:software-b73ef432-7f6a-4fb7-b5ca-b4406c42e632\" " +
				"            xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"indicator:IndicatorType\"> " +
				"            <indicator:Title>Software</indicator:Title> " +
				"            <indicator:Observable idref=\"stucco:software-b73ef432-7f6a-4fb7-b5ca-b4406c42e632\"/> " +
				"            <indicator:Related_Packages> " +
				"                <stixCommon:Package_Reference idref=\"stucco:vulnerability-0958d640-cecf-42b2-a6f3-14e0206bf87f\"> " +
				"                    <stixCommon:Relationship>Has vulnerability</stixCommon:Relationship> " +
				"                </stixCommon:Package_Reference> " +
				"            </indicator:Related_Packages> " +
				"        </stix:Indicator> " +
				"    </stix:Indicators> " +
				"    <stix:Exploit_Targets> " +
				"        <stixCommon:Exploit_Target " +
				"            id=\"stucco:vulnerability-0958d640-cecf-42b2-a6f3-14e0206bf87f\" " +
				"            xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"et:ExploitTargetType\"> " +
				"            <et:Title>Vulnerability</et:Title> " +
				"            <et:Vulnerability> " +
				"                <et:Description>Cross-site scripting (XSS) vulnerability in HP System Management Homepage (SMH) before 7.2.1 allows remote attackers to inject arbitrary web script or HTML via unspecified vectors.</et:Description> " +
				"                <et:CVE_ID>CVE-2013-2361</et:CVE_ID> " +
				"                <et:Source>NVD</et:Source> " +
				"                <et:Published_DateTime>2013-07-22T07:19:36.000-04:00</et:Published_DateTime> " +
				"                <et:Affected_Software> " +
				"                    <et:Affected_Software> " +
				"                        <stixCommon:Observable idref=\"stucco:software-b73ef432-7f6a-4fb7-b5ca-b4406c42e632\"/> " +
				"                    </et:Affected_Software> " +
				"                </et:Affected_Software> " +
				"                <et:References> " +
				"                    <stixCommon:Reference>https://h20564.www2.hp.com/portal/site/hpsc/public/kb/docDisplay?docId=emr_na-c03839862</stixCommon:Reference> " +
				"                    <stixCommon:Reference>SOURCE:description</stixCommon:Reference> " +
				"                </et:References> " +
				"            </et:Vulnerability> " +
				"        </stixCommon:Exploit_Target> " +
				"    </stix:Exploit_Targets> " +
				"</stix:STIX_Package> ";

			NvdToStixExtractor nvdExt = new NvdToStixExtractor(nvdInfo);
			STIXPackage receivedPackage = nvdExt.getStixPackage();
			STIXPackage expectedPackage = new STIXPackage().fromXMLString(expectedVerts);
						
			assertTrue(nvdExt.validate(receivedPackage));
			assertTrue(HTMLExtractor.compareStixPackages(receivedPackage, expectedPackage));			

		} catch (IOException e)	{
			e.printStackTrace();
		}
	}

	/**
	 * Tests nvd with tree entries
	 */
	@Test
	public void test_three_entries()	{
			
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

			String expectedVerts =
				"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " +
				"<stix:STIX_Package id=\"stucco:NVD-bffd0ce4-ba58-4966-ac6e-49759e89746b\" " +
				"    timestamp=\"2015-07-28T00:02:30.437Z\" " +
				"    xmlns=\"http://xml/metadataSharing.xsd\" " +
				"    xmlns:ProductObj=\"http://cybox.mitre.org/objects#ProductObject-2\" " +
				"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" " +
				"    xmlns:cyboxCommon=\"http://cybox.mitre.org/common-2\" " +
				"    xmlns:et=\"http://stix.mitre.org/ExploitTarget-1\" " +
				"    xmlns:indicator=\"http://stix.mitre.org/Indicator-2\" " +
				"    xmlns:stix=\"http://stix.mitre.org/stix-1\" " +
				"    xmlns:stixCommon=\"http://stix.mitre.org/common-1\" xmlns:stucco=\"gov.ornl.stucco\"> " +
				"    <stix:STIX_Header> " +
				"        <stix:Title>NVD</stix:Title> " +
				"    </stix:STIX_Header> " +
				"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\"> " +
				"        <cybox:Observable id=\"stucco:software-32522588-c5cf-44fb-ae98-afd14bb2187e\"> " +
				"            <cybox:Title>Software</cybox:Title> " +
				"            <cybox:Observable_Source name=\"NVD\"> " +
				"                <cyboxCommon:Information_Source_Type>National Vulnerability Database</cyboxCommon:Information_Source_Type> " +
				"            </cybox:Observable_Source> " +
				"            <cybox:Object> " +
				"                <cybox:Description>parallels parallels_plesk_panel version 9.2</cybox:Description> " +
				"                <cybox:Properties " +
				"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"ProductObj:ProductObjectType\"> " +
				"                    <ProductObj:Product>cpe:/a:parallels:parallels_plesk_panel:9.2</ProductObj:Product> " +
				"                </cybox:Properties> " +
				"            </cybox:Object> " +
				"        </cybox:Observable> " +
				"        <cybox:Observable id=\"stucco:software-428d507e-6fb8-4117-a1a5-29ada8dac983\"> " +
				"            <cybox:Title>Software</cybox:Title> " +
				"            <cybox:Observable_Source name=\"NVD\"> " +
				"                <cyboxCommon:Information_Source_Type>National Vulnerability Database</cyboxCommon:Information_Source_Type> " +
				"            </cybox:Observable_Source> " +
				"            <cybox:Object> " +
				"                <cybox:Description>parallels parallels_small_business_panel version 10.0</cybox:Description> " +
				"                <cybox:Properties " +
				"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"ProductObj:ProductObjectType\"> " +
				"                    <ProductObj:Product>cpe:/a:parallels:parallels_small_business_panel:10.0</ProductObj:Product> " +
				"                </cybox:Properties> " +
				"            </cybox:Object> " +
				"        </cybox:Observable> " +
				"        <cybox:Observable id=\"stucco:software-be5e054f-ebc1-46c3-83e8-1c43bc2152d5\"> " +
				"            <cybox:Title>Software</cybox:Title> " +
				"            <cybox:Observable_Source name=\"NVD\"> " +
				"                <cyboxCommon:Information_Source_Type>National Vulnerability Database</cyboxCommon:Information_Source_Type> " +
				"            </cybox:Observable_Source> " +
				"            <cybox:Object> " +
				"                <cybox:Description>parallels parallels_plesk_panel version 9.0</cybox:Description> " +
				"                <cybox:Properties " +
				"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"ProductObj:ProductObjectType\"> " +
				"                    <ProductObj:Product>cpe:/a:parallels:parallels_plesk_panel:9.0</ProductObj:Product> " +
				"                </cybox:Properties> " +
				"            </cybox:Object> " +
				"        </cybox:Observable> " +
				"    </stix:Observables> " +
				"    <stix:Indicators> " +
				"        <stix:Indicator " +
				"            id=\"stucco:software-32522588-c5cf-44fb-ae98-afd14bb2187e\" " +
				"            xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"indicator:IndicatorType\"> " +
				"            <indicator:Title>Software</indicator:Title> " +
				"            <indicator:Observable idref=\"stucco:software-32522588-c5cf-44fb-ae98-afd14bb2187e\"/> " +
				"            <indicator:Related_Packages> " +
				"                <stixCommon:Package_Reference idref=\"stucco:vulnerability-05843f15-0ecf-4d48-9f0b-e06b692c3635\"> " +
				"                    <stixCommon:Relationship>Has vulnerability</stixCommon:Relationship> " +
				"                </stixCommon:Package_Reference> " +
				"            </indicator:Related_Packages> " +
				"        </stix:Indicator> " +
				"        <stix:Indicator " +
				"            id=\"stucco:software-428d507e-6fb8-4117-a1a5-29ada8dac983\" " +
				"            xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"indicator:IndicatorType\"> " +
				"            <indicator:Title>Software</indicator:Title> " +
				"            <indicator:Observable idref=\"stucco:software-428d507e-6fb8-4117-a1a5-29ada8dac983\"/> " +
				"            <indicator:Related_Packages> " +
				"                <stixCommon:Package_Reference idref=\"stucco:vulnerability-dd984808-d864-4427-a815-156641c86c7b\"> " +
				"                    <stixCommon:Relationship>Has vulnerability</stixCommon:Relationship> " +
				"                </stixCommon:Package_Reference> " +
				"            </indicator:Related_Packages> " +
				"        </stix:Indicator> " +
				"        <stix:Indicator " +
				"            id=\"stucco:software-be5e054f-ebc1-46c3-83e8-1c43bc2152d5\" " +
				"            xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"indicator:IndicatorType\"> " +
				"            <indicator:Title>Software</indicator:Title> " +
				"            <indicator:Observable idref=\"stucco:software-be5e054f-ebc1-46c3-83e8-1c43bc2152d5\"/> " +
				"            <indicator:Related_Packages> " +
				"                <stixCommon:Package_Reference idref=\"stucco:vulnerability-dd984808-d864-4427-a815-156641c86c7b\"> " +
				"                    <stixCommon:Relationship>Has vulnerability</stixCommon:Relationship> " +
				"                </stixCommon:Package_Reference> " +
				"            </indicator:Related_Packages> " +
				"        </stix:Indicator> " +
				"    </stix:Indicators> " +
				"    <stix:Exploit_Targets> " +
				"        <stixCommon:Exploit_Target " +
				"            id=\"stucco:vulnerability-ddf26a03-5d1a-477e-9d49-670704d20fbc\" " +
				"            xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"et:ExploitTargetType\"> " +
				"            <et:Title>Vulnerability</et:Title> " +
				"            <et:Vulnerability> " +
				"                <et:CVE_ID>CVE-2099-0001</et:CVE_ID> " +
				"                <et:Source>NVD</et:Source> " +
				"            </et:Vulnerability> " +
				"        </stixCommon:Exploit_Target> " +
				"        <stixCommon:Exploit_Target " +
				"            id=\"stucco:vulnerability-05843f15-0ecf-4d48-9f0b-e06b692c3635\" " +
				"            xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"et:ExploitTargetType\"> " +
				"            <et:Title>Vulnerability</et:Title> " +
				"            <et:Vulnerability> " +
				"                <et:CVE_ID>CVE-2099-0002</et:CVE_ID> " +
				"                <et:Source>NVD</et:Source> " +
				"                <et:Affected_Software> " +
				"                    <et:Affected_Software> " +
				"                        <stixCommon:Observable idref=\"stucco:software-32522588-c5cf-44fb-ae98-afd14bb2187e\"/> " +
				"                    </et:Affected_Software> " +
				"                </et:Affected_Software> " +
				"            </et:Vulnerability> " +
				"        </stixCommon:Exploit_Target> " +
				"        <stixCommon:Exploit_Target " +
				"            id=\"stucco:vulnerability-dd984808-d864-4427-a815-156641c86c7b\" " +
				"            xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"et:ExploitTargetType\"> " +
				"            <et:Title>Vulnerability</et:Title> " +
				"            <et:Vulnerability> " +
				"                <et:CVE_ID>CVE-2099-0003</et:CVE_ID> " +
				"                <et:Source>NVD</et:Source> " +
				"                <et:Affected_Software> " +
				"                    <et:Affected_Software> " +
				"                        <stixCommon:Observable idref=\"stucco:software-428d507e-6fb8-4117-a1a5-29ada8dac983\"/> " +
				"                    </et:Affected_Software> " +
				"                    <et:Affected_Software> " +
				"                        <stixCommon:Observable idref=\"stucco:software-be5e054f-ebc1-46c3-83e8-1c43bc2152d5\"/> " +
				"                    </et:Affected_Software> " +
				"                    <et:Affected_Software> " +
				"                        <stixCommon:Observable idref=\"stucco:software-32522588-c5cf-44fb-ae98-afd14bb2187e\"/> " +
				"                    </et:Affected_Software> " +
				"                </et:Affected_Software> " +
				"            </et:Vulnerability> " +
				"        </stixCommon:Exploit_Target> " +
				"    </stix:Exploit_Targets> " +
				"</stix:STIX_Package> ";


			NvdToStixExtractor nvdExt = new NvdToStixExtractor(nvdInfo);
			STIXPackage receivedPackage = nvdExt.getStixPackage();
			STIXPackage expectedPackage = new STIXPackage().fromXMLString(expectedVerts);
										
			assertTrue(nvdExt.validate(receivedPackage));
			assertTrue(HTMLExtractor.compareStixPackages(receivedPackage, expectedPackage));			
	}
	
	/**
	 * Tests nvd with two entries
	 */
	@Test
	public void test_two_entries()	{
			
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

			String expectedVerts =
				"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " +
				"<stix:STIX_Package id=\"stucco:NVD-9bd57594-f83a-43ef-9cb4-1f6cf806a88c\" " +
				"    timestamp=\"2015-07-28T00:12:46.164Z\" " +
				"    xmlns:et=\"http://stix.mitre.org/ExploitTarget-1\" " +
				"    xmlns:stix=\"http://stix.mitre.org/stix-1\" " +
				"    xmlns:stixCommon=\"http://stix.mitre.org/common-1\" xmlns:stucco=\"gov.ornl.stucco\"> " +
				"    <stix:STIX_Header> " +
				"        <stix:Title>NVD</stix:Title> " +
				"    </stix:STIX_Header> " +
				"    <stix:Exploit_Targets> " +
				"        <stixCommon:Exploit_Target " +
				"            id=\"stucco:vulnerability-42708c0c-eb4e-42c0-8299-3f67e683fbd9\" " +
				"            xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"et:ExploitTargetType\"> " +
				"            <et:Title>Vulnerability</et:Title> " +
				"            <et:Vulnerability> " +
				"                <et:Description>The default configuration of Parallels Plesk Panel 9.0.x and 9.2.x on UNIX, and Small Business Panel 10.x on UNIX, has an improper ScriptAlias directive for phppath, which makes it easier for remote attackers to execute arbitrary code via a crafted request, a different vulnerability than CVE-2012-1823.</et:Description> " +
				"                <et:CVE_ID>CVE-2013-4878</et:CVE_ID> " +
				"                <et:Source>NVD</et:Source> " +
				"                <et:CVSS_Score> " +
				"                    <et:Base_Score>6.8</et:Base_Score> " +
				"                </et:CVSS_Score> " +
				"                <et:Published_DateTime>2013-07-18T12:51:56.000-04:00</et:Published_DateTime> " +
				"            </et:Vulnerability> " +
				"        </stixCommon:Exploit_Target> " +
				"        <stixCommon:Exploit_Target " +
				"            id=\"stucco:vulnerability-697ab139-974b-4029-9075-416d85aeeb13\" " +
				"            xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"et:ExploitTargetType\"> " +
				"            <et:Title>Vulnerability</et:Title> " +
				"            <et:Vulnerability> " +
				"                <et:Description>** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: CVE-2012-5217. Reason: This candidate is a duplicate of CVE-2012-5217. A typo caused the wrong ID to be used. Notes: All CVE users should reference CVE-2012-5217 instead of this candidate. All references and descriptions in this candidate have been removed to prevent accidental usage.</et:Description> " +
				"                <et:CVE_ID>CVE-2013-5217</et:CVE_ID> " +
				"                <et:Source>NVD</et:Source> " +
				"                <et:Published_DateTime>2013-07-18T12:51:56.000-04:00</et:Published_DateTime> " +
				"            </et:Vulnerability> " +
				"        </stixCommon:Exploit_Target> " +
				"    </stix:Exploit_Targets> " +
				"</stix:STIX_Package> ";

			NvdToStixExtractor nvdExt = new NvdToStixExtractor(nvdInfo);
			STIXPackage receivedPackage = nvdExt.getStixPackage();
			STIXPackage expectedPackage = new STIXPackage().fromXMLString(expectedVerts);
			
			assertTrue(nvdExt.validate(receivedPackage));
			assertTrue(HTMLExtractor.compareStixPackages(receivedPackage, expectedPackage));			
	}		


	/**
	 * extract ~5M document
	 */
	@Test
	public void test_extract_5M()	{
		try {
			File nvdFile = new File("./testData/nvd/nvdcve-2.0-2002_pt1.xml");
			Charset charset = Charset.defaultCharset();
			String nvdInfo = FileUtils.readFileToString(nvdFile, charset);
			
			NvdToStixExtractor nvdExt = new NvdToStixExtractor(nvdInfo);
			STIXPackage receivedPackage = nvdExt.getStixPackage();
						
			assertTrue(nvdExt.validate(receivedPackage));
		} catch (IOException e)	{
			e.printStackTrace();
		}

	}
}
