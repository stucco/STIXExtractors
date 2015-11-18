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
public class CleanMxVirusExtractorTest extends STIXExtractor {
	
	/**
	 * Test one element
	 */
	@Test
	public void test_one_element() {

		System.out.println();
		System.out.println("STIXExtractor.CleanMxVirusExtractorTest.test_one_element()");

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

		System.out.println(stixPackage.toXMLString(true));

		assertTrue(virusExtractor.validate(stixPackage));

		Document doc = Jsoup.parse(stixPackage.toXMLString(), "", Parser.xmlParser());
		
		/* Testing Malware */
		System.out.println("Testing Malware content");
		Elements elements = doc.select("stix|TTP");
		
		assertTrue(elements.size() == 1);

		for (Element element : elements) {
			
			System.out.println("Testing Name");
			assertEquals(element.select("ttp|Name").text(), "CleanMx(virus)_22447134");
			System.out.println("Testing Description");
			assertEquals(element.select("ttp|description").text(), "CleanMx(virus) entry 22447134");
			System.out.println("Testing Source");
			assertEquals(element.select("stixcommon|name").text(), "CleanMx(virus)");
			System.out.println("Testing Title");
			assertEquals(element.select(" > ttp|Behavior > ttp|Malware > ttp|Malware_Instance >  ttp|title").text(), "CleanMx(virus)_22447134");
			System.out.println("Testing Hash Value");
			assertEquals(element.select("cyboxcommon|simple_hash_value").text(), "b5bcb300eb41207d0d945b79c364a0b5");
		}
		
		/* Testing Address */
		System.out.println();
		System.out.println("Testing Address content");
		elements = doc.select("cybox|Observable:has(cybox|Title:matches(^Address\\Z))");
		
		assertTrue(elements.size() == 1);

		for (Element element : elements) {

			/* Testing Aaddress -> IP */
			System.out.println("Testing Address -> IP relation");
			String sourceIpId = element.select("SocketAddressObj|IP_Address").attr("object_reference");
			String ip = doc.select("[id= " + sourceIpId + "] > cybox|Object > cybox|Properties > AddressObj|Address_Value").text();
			assertEquals(ip, "115.47.55.160");
			
			/* Testing Address -> Port */
			System.out.println("Testing Address -> Port relation");
			String sourcePortId = element.select("SocketAddressObj|Port").attr("object_reference");
			String port = doc.select("[id= " + sourcePortId + "] > cybox|Object > cybox|Properties > PortObj|Port_Value").text();
			assertEquals(port, "80");

			assertEquals(element.select("cybox|Object > cybox|description").text(), "115.47.55.160, port 80");
			assertEquals(element.select("cybox|Observable_Source > cyboxcommon|information_source_type").text(), "CleanMx(virus)");
			assertEquals(element.select("cybox|title").text(), "Address");
		}
		
		/* Testing Port	*/
		System.out.println();
		System.out.println("Testing Port content");
		elements = doc.select("cybox|Observable:has(cybox|Title:matches(^Port\\Z))");
		
		assertTrue(elements.size() == 1);

		for (Element element : elements) {
			System.out.println("Testing Port Value");
			assertEquals(element.select("portobj|port_value").text(), "80");
			System.out.println("Testing Description");
			assertEquals(element.select("cybox|description").text(), "80");
			System.out.println("Testing Source");
			assertEquals(element.select("cyboxcommon|information_source_type").text(), "CleanMx(virus)");
			System.out.println("Testing Title");
			assertEquals(element.select("cybox|title").text(), "Port");
		}
		/* Testing DNSName */		
		System.out.println();
		System.out.println("Testing DNSName content");
		elements = doc.select("cybox|Observable:has(cybox|Title:matches(^DNSName\\Z))");
		
		assertTrue(elements.size() == 1);

		for (Element element : elements) {
			System.out.println("Testing Name");
			assertEquals(element.select("DomainNameObj|Value").text(), "idba.cc");
			System.out.println("Testing Description");
			assertEquals(element.select("cybox|description").text(), "idba.cc");
			System.out.println("Testing Source");
			assertEquals(element.select("cyboxcommon|information_source_type").text(), "CleanMx(virus)");
			System.out.println("Testing DNSName");
			assertEquals(element.select("cybox|title").text(), "DNSName");

			System.out.println("Testing NS");
			Elements ns = element.select("whoisobj|nameserver > uriobj|value");
			
			assertTrue(ns.size() == 2);
			assertTrue(ns.select("uriobj|value:matches(^f1g1ns1.dnspod.net\\Z)").size() == 1);
			assertTrue(ns.select("uriobj|value:matches(^f1g1ns2.dnspod.net\\Z)").size() == 1);
		}

		/* Testing IP */
		System.out.println();
		System.out.println("Testing IP content");
		elements = doc.select("cybox|Observable:has(cybox|Title:matches(^IP\\Z))");
		
		assertTrue(elements.size() == 1);

		for (Element element : elements) {
			System.out.println("Testing IP Value");
			assertEquals(element.select("addressobj|address_value").text(), "115.47.55.160");
			System.out.println("Testing Description");
			assertEquals(element.select("cybox|Object >  cybox|description").text(), "115.47.55.160");
			System.out.println("Testing Source");
			assertEquals(element.select("cybox|Observable_Source > cyboxcommon|information_source_type").text(), "CleanMx(virus)");
			System.out.println("Testing Title");
			assertEquals(element.select("cybox|title").text(), "IP");
		}
   		
		/* Testing AddressRange	*/	
		System.out.println();
		System.out.println("Testing AddressRange content");
		elements = doc.select("cybox|Observable:has(cybox|Title:matches(^AddressRange\\Z))");
		
		assertTrue(elements.size() == 1);

		for (Element element : elements) {
			System.out.println("Testing IP Value");
			assertEquals(element.select("addressobj|address_value").text(), "115.47.0.0 - 115.47.255.255");
			System.out.println("Testing Description");
			assertEquals(element.select("cybox|description").text(), "Netname XRNET: Beijing XiRang Media Cultural Co., Ltd.Build A6-1702,Fenghuahaojing,No.6 Guanganmennei RoadXuanwu, Beijing, China, 100053");
			System.out.println("Testing Source");
			assertEquals(element.select("cybox|Observable_Source > cyboxcommon|information_source_type").text(), "CleanMx(virus)");
			System.out.println("Testing Title");
			assertEquals(element.select("cybox|title").text(), "AddressRange");
			System.out.println("Testing Country");
			assertEquals(element.select("cybox|location > cyboxcommon|name").text(), "CN");
			System.out.println("Testing Netname");
			String[] netname = element.select("cybox|description").text().split(":");
			assertEquals(netname[0], "Netname XRNET");
		}
		
		/* Malware -> Address */
		System.out.println("Testing Malware -> Address relation");

		String malwareAddressIdref = doc.select("ttp|Observable_Characterization > cybox|Observable").attr("idref");
		String addressId = doc.select("cybox|Observable:has(cybox|Title:matches(^Address\\Z))").attr("id");

		assertEquals(malwareAddressIdref, addressId);
		
		/* Address -> DNSName */
		System.out.println("Testing Address -> DNSName relation");
		
		Elements relatedObjects = doc.select("cybox|Observable:has(cybox|Title:matches(^Address\\Z)) > cybox|Object > cybox|Related_Objects"); 
		String addressToDnsIdref = relatedObjects.select("cybox|Related_Object").attr("idref");
		String dnsId = doc.select("cybox|Observable:has(cybox|Title:matches(^DNSName\\Z))").attr("id");

		assertEquals(addressToDnsIdref, dnsId);

		String description = relatedObjects.select("cybox|Related_Object > cybox|Description").text();

		assertEquals(description, "115.47.55.160, port 80 has DNS name idba.cc");

		/* IP -> AddressRange */
		System.out.println("Testing IP -> AddressRange relation");
		
		Element ip = doc.select("cybox|Observable:has(cybox|Title:contains(IP))").first();
		String ipToAddressRangeIdref = ip.select("cybox|Related_Object").attr("idref");
		String addressRangeId = doc.select("cybox|Observable:has(cybox|Title:contains(AddressRange))").attr("id");

		assertEquals(ipToAddressRangeIdref, addressRangeId);

		description = ip.select("cybox|Related_Object > cybox|Description").text();

		assertEquals(description, "115.47.55.160 is in address range 115.47.0.0 through 115.47.255.255");
			
	}
	
	/**
	 * Test two elements
	 */
	@Test
	public void test_two_elements() {
		
	System.out.println();
	System.out.println("STIXExtractor.CleanMxVirusExtractorTest.test_two_elements()");
		
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

		Document cleanMxDoc = Jsoup.parse(cleanMxInfo);
		Document stixDoc = Jsoup.parse(stixPackage.toXMLString(), "", Parser.xmlParser());
		
		/* Testing Malware */
		System.out.println("Testing Malware content:");
		Elements cleanMxElements = Jsoup.parse(cleanMxInfo).select("entry");
		Elements stixElements = stixDoc.select("stix|Indicator");
		
		for (Element element : stixElements) {
			if (element.select("ttp|Description").text().equals("CleanMx(virus) entry 22446016")) {
				Element givenElement = cleanMxElements.select("entry:has(id:matches(^22446016$)").first();
				System.out.println("Testing Name");
				Elements names = element.select("ttp|Name");
				for (Element name: names) {
					if (name.text().equals("CleanMx(virus)_" + givenElement.select("id").text())) {
						continue;
					} else {
						if (name.text().equals(givenElement.select("virusname").text())) {
							continue;
						} else {
							System.out.println("ERROR: Cannot find Name" + name.text());
							assertTrue(false);
						}
					}
					assertEquals(element.select("ttp|Name").text(), "CleanMx(virus)_" + givenElement.select("id").text());
				}
				System.out.println("Testing Description");
				assertEquals(element.select("ttp|description").text(), "CleanMx(virus) entry " + givenElement.select("id").text());
				System.out.println("Testing Source");
				assertEquals(element.select("stixcommon|name").text(), "CleanMx(virus)");
				System.out.println("Testing Title");
				assertEquals(element.select("ttp|title").text(), "Malware");
				System.out.println("Testing Hash value");
				assertEquals(element.select("cyboxcommon|simple_hash_value").text(), givenElement.select("md5").text());
				System.out.println("Testing Malware -> Address relation");
				String idref = element.select("indicator|Observable").attr("idref");
				String ipRef = stixDoc.select("[id=" + idref + "]").select("SocketAddressObj|IP_Address").attr("object_reference");
				String ip = stixDoc.select("[id=" + ipRef + "]").select("AddressObj|Address_Value").text();
				assertEquals(ip, givenElement.select("ip").text());
				System.out.println("Testing Address -> Port relation");
				String portRef = stixDoc.select("[id=" + idref + "]").select("SocketAddressObj|Port").attr("object_reference");
				String port = stixDoc.select("[id=" + portRef + "]").select("PortObj|Port_Value").text();
				assertEquals(port, "80");
			} else {
				if (element.select("ttp|Description").text().equals("CleanMx(virus) entry 22446014")) {
					Element givenElement = cleanMxElements.select("entry:has(id:matches(^22446014$)").first();
					System.out.println("Testing Name");
					Elements names = element.select("ttp|Name");
					for (Element name: names) {
						if (name.text().equals("CleanMx(virus)_" + givenElement.select("id").text())) {
							continue;
						} else {
							if (name.text().equals(givenElement.select("virusname").text())) {
								continue;
							} else {
								System.out.println("ERROR: Cannot find Name" + name.text());
								assertTrue(false);
							}
						}
						assertEquals(element.select("ttp|Name").text(), "CleanMx(virus)_" + givenElement.select("id").text());
					}
					System.out.println("Testing Description");
					assertEquals(element.select("ttp|description").text(), "CleanMx(virus) entry " + givenElement.select("id").text());
					System.out.println("Testing Source");
					assertEquals(element.select("stixcommon|name").text(), "CleanMx(virus)");
					System.out.println("Testing Title");
					assertEquals(element.select("ttp|title").text(), "Malware");
					System.out.println("Testing Hash value");
					assertEquals(element.select("cyboxcommon|simple_hash_value").text(), givenElement.select("md5").text());
					System.out.println("Testing Malware -> Address relation");
					
					System.out.println("Testing Address -> IP relation");
					String idref = element.select("indicator|Observable").attr("idref");
					String ipRef = stixDoc.select("[id=" + idref + "]").select("SocketAddressObj|IP_Address").attr("object_reference");
					String ip = stixDoc.select("[id=" + ipRef + "]").select("AddressObj|Address_Value").text();
					assertEquals(ip, givenElement.select("ip").text());
					
					System.out.println("Testing Address -> Port relation");
					String portRef = stixDoc.select("[id=" + idref + "]").select("SocketAddressObj|Port").attr("object_reference");
					String port = stixDoc.select("[id=" + portRef + "]").select("PortObj|Port_Value").text();
					assertEquals(port, "80");
				} else {
					System.out.println(element.select("ttp|Name"));
					System.out.println("ERROR: Could not find Malware Indicator");
					assertTrue(false);
				}
			}			
		}		
		
		/* Testing Addresses */
		System.out.println();
		System.out.println("Testing Address content:");
	
		for (Element address : cleanMxElements) {
			Element stixAddress = stixDoc.select("cybox|Observable:has(cybox|Object[id=stucco:address-" + ipToLong(address.select("ip").text()) + "_80]").first();
			System.out.println("Testing ID");
			assertEquals(stixAddress.select("cybox|Object").attr("id"), "stucco:address-" + ipToLong(address.select("ip").text()) + "_80");
			System.out.println("Testing Title");
			assertEquals(stixAddress.select("cybox|Title").text(), "Address");
			System.out.println("Testing Source");
			assertEquals(stixAddress.select("cybox|Observable_Source > cyboxCommon|Information_Source_Type").text(), "CleanMx(virus)");
			System.out.println("Testing Description");
			assertEquals(stixAddress.select("cybox|Object > cybox|Description").text(), address.select("ip").text() + ", port 80");

			System.out.println("Testing Address -> IP reference");
			String ipId = stixAddress.select("SocketAddressObj|IP_Address").attr("object_reference");
			String ip = stixDoc.select("[id= " + ipId + "] > cybox|Object > cybox|Properties > AddressObj|Address_Value").text();
			assertEquals(ip, address.select("ip").text());

			System.out.println("Testing Address -> Port reference");
			String portId = stixAddress.select("SocketAddressObj|Port").attr("object_reference");
			String port = stixDoc.select("[id= " + portId + "] > cybox|Object > cybox|Properties > PortObj|Port_Value").text();
			assertEquals(port, "80");

			System.out.println("Testing Address -> DNSName");
			String dnsRef = stixAddress.select("cybox|Related_Object").attr("idref");
			String dnsValue = stixDoc.select("[id=" + dnsRef + "]").select("DomainNameObj|Value").text();
			assertEquals(dnsValue, address.select("domain").text());
		}

		/* Testing Ports */
		System.out.println();
		System.out.println("Testing Port content:");
	
		for (Element port : cleanMxElements) {
			Element stixPort = stixDoc.select("cybox|Observable:has(cybox|Object[id=stucco:port-80])").first();
			System.out.println("Testing Title");
			assertEquals(stixPort.select("cybox|Title").text(), "Port");
			System.out.println("Testing Source");
			assertEquals(stixPort.select("cybox|Observable_Source > cyboxCommon|Information_Source_Type").text(), "CleanMx(virus)");
			System.out.println("Testing ID");
			assertEquals(stixPort.select("cybox|Object").attr("id"), "stucco:port-80");
			System.out.println("Testing Port value");
			assertEquals(stixPort.select("PortObj|Port_Value").text(), "80");
			System.out.println("Testing Description");
			assertEquals(stixPort.select("cybox|Object > cybox|Description").text(), "80");
		}
		
		/* Testing DNSName */
		System.out.println();
		System.out.println("Testing DNSName content:");
	
		for (Element dns : cleanMxElements) {
			Element stixDns = stixDoc.select("cybox|Observable:has(cybox|Object[id=stucco:dnsName-" + dns.select("domain").text() + "])").first();
			System.out.println("Testing Title");
			assertEquals(stixDns.select("cybox|Title").text(), "DNSName");
			System.out.println("Testing Source");
			assertEquals(stixDns.select("cybox|Observable_Source > cyboxCommon|Information_Source_Type").text(), "CleanMx(virus)");
			System.out.println("Testing ID");
			assertEquals(stixDns.select("cybox|Object").attr("id"), "stucco:dnsName-" + dns.select("domain").text());
			System.out.println("Testing Domain name");
			assertEquals(stixDns.select("DomainNameObj|Value").text(), dns.select("domain").text());
			System.out.println("Testing Description");
			assertEquals(stixDns.select("cybox|Object > cybox|Description").text(), dns.select("domain").text());
			System.out.println("Testing Namespace");
		}
		
		/* Testing IP */
		System.out.println();
		System.out.println("Testing IP content:");
	
		for (Element ip : cleanMxElements) {
			Element stixIp = stixDoc.select("cybox|Observable:has(cybox|Object[id=stucco:ip-" + ipToLong(ip.select("ip").text()) + "])").first();
			System.out.println("Testing Title");
			assertEquals(stixIp.select("cybox|Title").text(), "IP");
			System.out.println("Testing Source");
			assertEquals(stixIp.select("cybox|Observable_Source > cyboxCommon|Information_Source_Type").text(), "CleanMx(virus)");
			System.out.println("Testing ID");
			assertEquals(stixIp.select("cybox|Object").attr("id"), "stucco:ip-" + ipToLong(ip.select("ip").text()));
			System.out.println("Testing IP value");
			assertEquals(stixIp.select("AddressObj|Address_Value").text(), ip.select("ip").text());
			System.out.println("Testing Description");
			assertEquals(stixIp.select("cybox|Object > cybox|Description").text(), ip.select("ip").text());
			
			System.out.println("Testing IP -> AddressRange relation");
			String rangeRef = stixIp.select("cybox|Related_Object").attr("idref");
			Element address = stixDoc.select("[id=" + rangeRef + "]").first();
			String rangeValue = address.select("AddressObj|Address_Value").text();
			String[] ips = ip.select("inetnum").text().split("-");
			ips[0] = ips[0].trim();
			ips[1] = ips[1].trim();
			assertEquals(rangeValue, ips[0] + " - " + ips[1]);
		}
		
		/* Testing AddressRange */
		System.out.println();
		System.out.println("Testing AddressRange content:");
	
		for (Element address : cleanMxElements) {
			String[] ip = address.select("inetnum").text().split("-");
			ip[0] = ip[0].trim();
			ip[1] = ip[1].trim();
			Element stixRange = stixDoc.select("cybox|Observable:has(cybox|Object[id=stucco:addressRange-" + ipToLong(ip[0]) + "-" + ipToLong(ip[1]) + "])").first();
			System.out.println("Testing Title");
			assertEquals(stixRange.select("cybox|Title").text(), "AddressRange");
			System.out.println("Testing Source");
			assertEquals(stixRange.select("cybox|Observable_Source > cyboxCommon|Information_Source_Type").text(), "CleanMx(virus)");
			System.out.println("Testing ID");
			assertEquals(stixRange.select("cybox|Object").attr("id"), "stucco:addressRange-" + ipToLong(ip[0]) + "-" + ipToLong(ip[1]));
			System.out.println("Testing IP values");
			assertEquals(stixRange.select("AddressObj|Address_Value").text(), ip[0] + " - " + ip[1]);
			System.out.println("Testing Description");
			assertEquals(stixRange.select("cybox|Object > cybox|Description").text(), "Netname " + address.select("netname").text() + ": " +address.select("descr").text());
			System.out.println("Testing Counrty");
			assertEquals(stixRange.select("cybox|Location > cyboxCommon|Name").text(), address.select("country").text());
		}
	}
}

