package STIXExtractor;

import java.io.File;
import java.io.IOException;
import java.io.StringReader;
import java.net.URL;
import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.Map;

import org.xml.sax.InputSource;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;

import org.json.JSONArray;
import org.json.JSONObject;

import org.json.*;
import org.jsoup.*;
import org.jsoup.parser.Parser;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import org.mitre.stix.stix_1.STIXPackage;

import org.junit.Test;

import static org.junit.Assert.*;

import STIXExtractor.CleanMxVirusExtractor;

/**
 * Unit test for Clean MX Virus Extracotr  List extractor.
 */
public class CleanMxVirusExtractorTest{
	
	/**
	 * Test one element
	 */
	@Test
	public void test_one_element()	{

		String cleanMxInfo =
			" <?xml version=\"1.0\" encoding=\"iso-8859-15\"?> " +
			"        <output> " +
			"            <response> " +
			"                <error>0</error> " +
			"            </response> " +
			"        <entries> " +
			"        <entry> " +
			"            <line>1</line> " +
			"            <id>22447134</id> " +
			"            <first>1394445736</first> " +
			"            <last>0</last> " +
			"            <md5>b5bcb300eb41207d0d945b79c364a0b5</md5> " +
			"            <virustotal></virustotal> " +
			"            <vt_score>0/43 (0.0%)</vt_score> " +
			"            <scanner></scanner> " +
			"            <virusname><![CDATA[]]></virusname> " +
			"            <url><![CDATA[http://xz.idba.cc:88/jqsp.zip?qqdrsign=050c5]]></url> " +
			"            <recent>up</recent> " +
			"            <response>alive</response> " +
			"            <ip>115.47.55.160</ip> " +
			"            <as>AS9395</as> " +
			"            <review>115.47.55.160</review> " +
			"            <domain>idba.cc</domain> " +
			"            <country>CN</country> " +
			"            <source>APNIC</source> " +
			"            <email>donglin@xrnet.cn</email> " +
			"            <inetnum>115.47.0.0 - 115.47.255.255</inetnum> " +
			"            <netname>XRNET</netname> " +
			"            <descr><![CDATA[Beijing XiRang Media Cultural Co., Ltd.Build A6-1702,Fenghuahaojing,No.6 Guanganmennei RoadXuanwu, Beijing, China, 100053]]></descr> " +
			"            <ns1>f1g1ns2.dnspod.net</ns1> " +
			"            <ns2>f1g1ns1.dnspod.net</ns2> " +
			"            <ns3></ns3> " +
			"            <ns4></ns4> " +
			"            <ns5></ns5> " +
			"        </entry> " +
			"        </entries> " +
			"        </output> ";
		
		CleanMxVirusExtractor virusExtractor = new CleanMxVirusExtractor(cleanMxInfo);
		STIXPackage stixPackage = virusExtractor.getStixPackage();

		assertTrue(virusExtractor.validate(stixPackage));

		Document doc = Jsoup.parse(stixPackage.toXMLString(), "", Parser.xmlParser());
//malware 
		System.out.println("Testing Malware content");
		Elements elements = doc.select("stixCommon|TTP");
		
		assertTrue(elements.size() == 1);

		for (Element element : elements)	{
			assertEquals(element.select("ttp|Name").text(), "CleanMx_22447134");
			assertEquals(element.select("ttp|description").text(), "CleanMx entry 22447134");
			assertEquals(element.select("stixcommon|name").text(), "CleanMx(virus)");
			assertEquals(element.select("ttp|title").text(), "Malware");
			assertEquals(element.select("cyboxcommon|simple_hash_value").text(), "b5bcb300eb41207d0d945b79c364a0b5");
		}
//Address
		System.out.println("Testing Address content");
		elements = doc.select("cybox|Observable:has(cybox|Title:matches(^Address\\Z))");
		
		assertTrue(elements.size() == 1);

		for (Element element : elements)	{
			assertEquals(element.select("addressobj|address_value").text(), "115.47.55.160:80");
			assertEquals(element.select("cybox|description").text(), "115.47.55.160, port 80");
			assertEquals(element.select("cyboxcommon|information_source_type").text(), "CleanMx(virus)");
			assertEquals(element.select("cybox|title").text(), "Address");
		}
//Port		
		System.out.println("Testing Port content");
		elements = doc.select("cybox|Observable:has(cybox|Title:matches(^Port\\Z))");
		
		assertTrue(elements.size() == 1);

		for (Element element : elements)	{
			assertEquals(element.select("portobj|port_value").text(), "80");
			assertEquals(element.select("cybox|description").text(), "80");
			assertEquals(element.select("cyboxcommon|information_source_type").text(), "CleanMx(virus)");
			assertEquals(element.select("cybox|title").text(), "Port");
		}
//DNSName		
		System.out.println("Testing DNSName content");
		elements = doc.select("cybox|Observable:has(cybox|Title:matches(^DNSName\\Z))");
		
		assertTrue(elements.size() == 1);

		for (Element element : elements)	{
			assertEquals(element.select("whoisobj|domain_name > uriobj|value").text(), "idba.cc");
			assertEquals(element.select("cybox|description").text(), "idba.cc");
			assertEquals(element.select("cyboxcommon|information_source_type").text(), "CleanMx(virus)");
			assertEquals(element.select("cybox|title").text(), "DNSName");

			Elements ns = element.select("whoisobj|nameserver > uriobj|value");
			
			assertTrue(ns.size() == 2);
			assertTrue(ns.select("uriobj|value:matches(^f1g1ns1.dnspod.net\\Z)").size() == 1);
			assertTrue(ns.select("uriobj|value:matches(^f1g1ns2.dnspod.net\\Z)").size() == 1);
		}
//IP
		System.out.println("Testing IP content");
		elements = doc.select("cybox|Observable:has(cybox|Title:matches(^IP\\Z))");
		
		assertTrue(elements.size() == 1);

		for (Element element : elements)	{
			assertEquals(element.select("addressobj|address_value").text(), "115.47.55.160");
			assertEquals(element.select("cybox|description").text(), "115.47.55.160");
			assertEquals(element.select("cyboxcommon|information_source_type").text(), "CleanMx(virus)");
			assertEquals(element.select("cybox|title").text(), "IP");
		}
//AddressRange		
		System.out.println("Testing AddressRange content");
		elements = doc.select("cybox|Observable:has(cybox|Title:matches(^AddressRange\\Z))");
		
		assertTrue(elements.size() == 1);

		for (Element element : elements)	{
			assertEquals(element.select("addressobj|address_value").text(), "115.47.0.0 - 115.47.255.255");
			assertEquals(element.select("cybox|description").text(), "Netname XRNET: Beijing XiRang Media Cultural Co., Ltd.Build A6-1702,Fenghuahaojing,No.6 Guanganmennei RoadXuanwu, Beijing, China, 100053");
			assertEquals(element.select("cyboxcommon|information_source_type").text(), "CleanMx(virus)");
			assertEquals(element.select("cybox|title").text(), "AddressRange");
			assertEquals(element.select("cybox|location > cyboxcommon|name").text(), "CN");
			String[] netname = element.select("cybox|description").text().split(":");
			assertEquals(netname[0], "Netname XRNET");
		}
//edges
		
//malware -> address
		System.out.println("Testing Malware to Address relation");

		String malwareAddressIdref = doc.select("stix|Indicators > stix|Indicator > indicator|Observable").attr("idref");
		String addressId = doc.select("cybox|Observable:has(cybox|Title:matches(^Address\\Z))").attr("id");

		assertEquals(malwareAddressIdref, addressId);
		
//address -> port
		System.out.println("Testing Address to Port relation");

		Elements relatedObjects = doc.select("cybox|Observable:has(cybox|Title:matches(^Address\\Z)) > cybox|Object > cybox|Related_Objects"); 
		String addressToPortIdref = relatedObjects.select("cybox|Related_Object:has(cybox|Relationship:matches(^address has port\\Z))").attr("idref");
		String portId = doc.select("cybox|Observable:has(cybox|Title:matches(^Port\\Z))").attr("id");

		assertEquals(addressToPortIdref, portId);

		String relationship = relatedObjects.select("cybox|Related_Object:has(cybox|Relationship:matches(^address has port\\Z))").text();

		assertEquals(relationship, "address has port");

//address -> DNSName
		System.out.println("Testing Address to DNSName relation");
		
		String addressToDnsIdref = relatedObjects.select("cybox|Related_Object:has(cybox|Relationship:matches(^address has DNS Name\\Z))").attr("idref");
		String dnsId = doc.select("cybox|Observable:has(cybox|Title:matches(^DNSName\\Z))").attr("id");

		assertEquals(addressToDnsIdref, dnsId);

		relationship = relatedObjects.select("cybox|Related_Object:has(cybox|Relationship:matches(^address has DNS Name\\Z))").text();

		assertEquals(relationship, "address has DNS Name");

//address -> IP
		System.out.println("Testing Address to IP relation");

		String addressToIpIdref = relatedObjects.select("cybox|Related_Object:has(cybox|Relationship:matches(^address has IP\\Z))").attr("idref");
		String ipId = doc.select("cybox|Observable:has(cybox|Title:matches(^IP\\Z))").attr("id");

		assertEquals(addressToIpIdref, ipId);

		relationship = relatedObjects.select("cybox|Related_Object:has(cybox|Relationship:matches(^address has IP\\Z))").text();

		assertEquals(relationship, "address has IP");

//IP -> addressRange
		System.out.println("Testing IP to AddressRange relation");
		
		relatedObjects = doc.select("cybox|Observable:has(cybox|Title:matches(^IP\\Z)) > cybox|Object > cybox|Related_Objects"); 
		String ipToAddressRangeIdref = relatedObjects.select("cybox|Related_Object:has(cybox|Relationship:matches(^IP is in address range\\Z))").attr("idref");
		String addressRangeId = doc.select("cybox|Observable:has(cybox|Title:matches(^AddressRange\\Z))").attr("id");

		assertEquals(ipToAddressRangeIdref, addressRangeId);

		relationship = relatedObjects.select("cybox|Related_Object:has(cybox|Relationship:matches(^IP is in address range\\Z))").text();

		assertEquals(relationship, "IP is in address range");
			
	}
	
	/**
	 * Test two elements
	 */
	@Test
	public void test_two_elements()	{
		
		String cleanMxInfo =
			"<?xml version=\"1.0\" encoding=\"iso-8859-15\"?> " +
			"        <output> " +
			"            <response> " +
			"                <error>0</error> " +
			"            </response> " +
			"        <entries> " +
			"        <entry> " +
			"            <line>7</line> " +
			"            <id>22446016</id> " +
			"            <first>1394445710</first> " +
			"            <last>0</last> " +
			"            <md5>dad1324061f93af4eb0205a3b114ea6e</md5> " +
			"            <virustotal>http://www.virustotal.com/latest-report.html?resource=dad1324061f93af4eb0205a3b114ea6e</virustotal> " +
			"            <vt_score>28/46 (60.9%)</vt_score> " +
			"            <scanner>AhnLab_V3</scanner> " +
			"            <virusname><![CDATA[Trojan%2FWin32.generic]]></virusname> " +
			"            <url><![CDATA[http://www.filedataukmyscan.info/sp32_64_18199873683419572808.exe]]></url> " +
			"            <recent>up</recent> " +
			"            <response>alive</response> " +
			"            <ip>95.211.169.207</ip> " +
			"            <as>AS16265</as> " +
			"            <review>95.211.169.207</review> " +
			"            <domain>filedataukmyscan.info</domain> " +
			"            <country>NL</country> " +
			"            <source>RIPE</source> " +
			"            <email>abuse@leaseweb.com</email> " +
			"            <inetnum>95.211.0.0 - 95.211.255.255</inetnum> " +
			"            <netname>NL-LEASEWEB-20080724</netname> " +
			"            <descr><![CDATA[LeaseWeb B.V.]]></descr> " +
			"            <ns1>brad.ns.cloudflare.com</ns1> " +
			"            <ns2>pam.ns.cloudflare.com</ns2> " +
			"            <ns3></ns3> " +
			"            <ns4></ns4> " +
			"            <ns5></ns5> " +
			"        </entry> " +
			"        <entry> " +
			"            <line>8</line> " +
			"            <id>22446014</id> " +
			"            <first>1394445710</first> " +
			"            <last>0</last> " +
			"            <md5>6653a885aae75cc8bd45f2808d80202c</md5> " +
			"            <virustotal>http://www.virustotal.com/latest-report.html?resource=6653a885aae75cc8bd45f2808d80202c</virustotal> " +
			"            <vt_score>13/45 (28.9%)</vt_score> " +
			"            <scanner>AntiVir</scanner> " +
			"            <virusname><![CDATA[Adware%2FLinkular.C]]></virusname> " +
			"            <url><![CDATA[http://www.coolestmovie.info/ds-exe/vlc/9076/VLCPlus_Setup.exe]]></url> " +
			"            <recent>up</recent> " +
			"            <response>alive</response> " +
			"            <ip>54.208.13.153</ip> " +
			"            <as>AS16509</as> " +
			"            <review>54.208.13.153</review> " +
			"            <domain>coolestmovie.info</domain> " +
			"            <country>US</country> " +
			"            <source>ARIN</source> " +
			"            <email>ec2-abuse@amazon.com</email> " +
			"            <inetnum>54.208.0.0 - 54.209.255.255</inetnum> " +
			"            <netname>AMAZO-ZIAD4</netname> " +
			"            <descr><![CDATA[Amazon.com, Inc. AMAZO-4 Amazon Web Services, Elastic Compute Cloud, EC2 1200 12th Avenue South Seattle WA 98144]]></descr> " +
			"            <ns1>ns58.domaincontrol.com</ns1> " +
			"            <ns2>ns57.domaincontrol.com</ns2> " +
			"            <ns3></ns3> " +
			"            <ns4></ns4> " +
			"            <ns5></ns5> " +
			"        </entry> " +
			"        </entries> " +
			"        </output> ";

		CleanMxVirusExtractor virusExtractor = new CleanMxVirusExtractor(cleanMxInfo);
		STIXPackage stixPackage = virusExtractor.getStixPackage();

		assertTrue(virusExtractor.validate(stixPackage));

		Document doc = Jsoup.parse(stixPackage.toXMLString(), "", Parser.xmlParser());

		Elements elements = doc.select("stixCommon|TTP");
		assertEquals(elements.size(), 2);
	}
}
