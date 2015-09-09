package STIXExtractor;

import java.util.ArrayList;
import java.util.List;
import java.util.HashMap;
import java.util.Map;

import java.io.File;
import java.io.IOException;

import java.net.URL;
import java.nio.charset.Charset;

import org.jsoup.Jsoup;
import org.jsoup.parser.Parser;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
	
import org.mitre.stix.stix_1.STIXPackage;

import STIXExtractor.SophosExtractor;
import STIXExtractor.STIXExtractor;

import org.junit.Test;

import static org.junit.Assert.*;

/**
 * Unit test for Sophos extractor.
 */
public class SophosExtractorTest extends STIXExtractor {
	
	private Map<String,String> loadContent(String entryName, boolean localMode) throws IOException{
		Map<String,String> pageContent = new HashMap<String,String>();
		String filePath = "./testData/sophos/";
		Charset charset = Charset.defaultCharset();
		if(localMode){
			File infoFD = new File(filePath + entryName + ".aspx");
			String info = FileUtils.readFileToString(infoFD, charset);
			pageContent.put("summary", info);
			
			File discussionFD = new File(filePath + entryName + "_details.aspx");
			String discussion = FileUtils.readFileToString(discussionFD, charset);
			pageContent.put("details", discussion);
		}
		else{
			URL u;
			u = new URL("http://www.sophos.com/en-us/threat-center/threat-analyses/viruses-and-spyware/"+entryName+".aspx");
			pageContent.put("summary", IOUtils.toString(u));
			
			u = new URL("http://www.sophos.com/en-us/threat-center/threat-analyses/viruses-and-spyware/"+entryName+"/detailed-analysis.aspx");
			pageContent.put("details", IOUtils.toString(u));
		}
		return pageContent;
	}
					
	/**
	 * Test with "Mal~Conficker-A" sample data
	 */
	@Test
	public void test_Mal_Conficker_A() {

		System.out.println();
		System.out.println("STIXExtractor.SophosExtractorTest.test_Mal_Conficker_A()");

		String entryName = "Mal~Conficker-A";
		boolean localMode = true;
		String summary, details;
		
		try {
			Map<String,String> pageContent = loadContent(entryName, localMode);
			summary = pageContent.get("summary");
			details = pageContent.get("details");
			
			SophosExtractor sophosExtractor = new SophosExtractor(summary, details);
			STIXPackage receivedPackage = sophosExtractor.getStixPackage();
			
			System.out.println("Validating StixPackage");					
			assertTrue(sophosExtractor.validate(receivedPackage));
			
			Document doc = Jsoup.parse(receivedPackage.toXMLString(), "", Parser.xmlParser());	
	
			Element indicator = doc.select("stix|Indicator").first();	
			System.out.println("Testing Title");
			assertEquals(indicator.select("ttp|Title").text(), "Malware");
			System.out.println("Testing Names");
			Elements names = doc.select("ttp|Name");
			List<String> nameList = new ArrayList<String>();
			for (Element name : names) {
				nameList.add(name.text());
			}
			assertTrue(nameList.contains("Mal/Conficker-A"));
			assertTrue(nameList.contains("Net-Worm.Win32.Kido"));
			assertTrue(nameList.contains("W32/Conficker.worm"));
			assertTrue(nameList.contains("WORM_DOWNAD.AD"));
			assertTrue(nameList.contains("Worm:W32/Downadup"));
			assertTrue(nameList.contains("Worm:Win32/Conficker.gen!A"));
			System.out.println("Testing Type");
			assertEquals(indicator.select("ttp|Type").text(), "Malicious behavior");
			System.out.println("Testing Description");
			assertEquals(indicator.select("ttp|Description").text(), "Mal/Conficker-A");
			System.out.println("Testing Platform");
			assertEquals(indicator.select("ttp|Targeted_Systems").text(), "Windows");
			System.out.println("Testing Source");
			assertEquals(indicator.select("stixCommon|Name").text(), "Sophos");

		} catch (IOException e) {
			e.printStackTrace();
			fail("IOException");
		} catch (Exception e) {
			e.printStackTrace();
			fail("Exception");
		}  
	}

	/**
	 * Test with "Troj~FBJack-A" sample data
	 */
	@Test
	public void test_Troj_FBJack_A() {
		System.out.println();
		System.out.println("STIXExtractor.SophosExtractorTest.test_Troj_FBJack_A()");
		
		String entryName = "Troj~FBJack-A";
		boolean localMode = true;
		String summary, details;
		
		try {
			Map<String,String> pageContent = loadContent(entryName, localMode);
			summary = pageContent.get("summary");
			details = pageContent.get("details");
			
			SophosExtractor sophosExtractor = new SophosExtractor(summary, details);
			STIXPackage receivedPackage = sophosExtractor.getStixPackage();
			
			System.out.println("Validating StixPackage");					
			assertTrue(sophosExtractor.validate(receivedPackage));
			
			Document doc = Jsoup.parse(receivedPackage.toXMLString(), "", Parser.xmlParser());	
	
			Element indicator = doc.select("stix|Indicator").first();	
			System.out.println("Testing Title");
			assertEquals(indicator.select("ttp|Title").text(), "Malware");
			System.out.println("Testing Names");
			Elements names = doc.select("ttp|Name");
			List<String> nameList = new ArrayList<String>();
			for (Element name : names) {
				nameList.add(name.text());
			}														
			assertTrue(nameList.contains("Troj/FBJack-A"));
			System.out.println("Testing Type");
			assertEquals(indicator.select("ttp|Type").text(), "Trojan");
			System.out.println("Testing Description");				
			assertEquals(indicator.select("ttp|Description").text(), "Troj/FBJack-A");
			System.out.println("Testing Platform");
			assertEquals(indicator.select("ttp|Targeted_Systems").text(), "Windows");
			System.out.println("Testing Source");
			assertEquals(indicator.select("stixCommon|Name").text(), "Sophos");
			
		} catch (IOException e) {
			e.printStackTrace();
			fail("IOException");
		} catch (Exception e) {
			e.printStackTrace();
			fail("Exception");
		}
	}

	/**
	 * Test with "Troj~Agent-DP" sample data
	 * (This entry is almost entirely free text, so not much to build here.)
	 */
	@Test
	public void test_Troj_Agent_DP() {
		System.out.println();
		System.out.println("STIXExtractor.SophosExtractorTest.test_Troj_Agent_DP()");
			
		String entryName = "Troj~Agent-DP";
		boolean localMode = true;
		String summary, details;
		
		try {
			Map<String,String> pageContent = loadContent(entryName, localMode);
			summary = pageContent.get("summary");
			details = pageContent.get("details");
			
			SophosExtractor sophosExtractor = new SophosExtractor(summary, details);
			STIXPackage receivedPackage = sophosExtractor.getStixPackage();

			System.out.println("Validating StixPackage");					
			assertTrue(sophosExtractor.validate(receivedPackage));
			
			Document doc = Jsoup.parse(receivedPackage.toXMLString(), "", Parser.xmlParser());	
	
			Element indicator = doc.select("stix|Indicator").first();	
			System.out.println("Testing Title");
			assertEquals(indicator.select("ttp|Title").text(), "Malware");
			System.out.println("Testing Names");
			Elements names = doc.select("ttp|Name");
			List<String> nameList = new ArrayList<String>();
			for (Element name : names) {
				nameList.add(name.text());
			}							
			assertTrue(nameList.contains("Troj/Agent-DP"));
			System.out.println("Testing Type");
			assertEquals(indicator.select("ttp|Type").text(), "Trojan");
			System.out.println("Testing Description");				
			assertEquals(indicator.select("ttp|Description").text(), "Troj/Agent-DP");
			System.out.println("Testing Platform");
			assertEquals(indicator.select("ttp|Targeted_Systems").text(), "Windows");
			System.out.println("Testing Source");
			assertEquals(indicator.select("stixCommon|Name").text(), "Sophos");

		} catch (IOException e) {
			e.printStackTrace();
			fail("IOException");
		} catch (Exception e) {
			e.printStackTrace();
			fail("Exception");
		}
	}
	
	/**
	 * Test with "Troj~Zbot-ITY" sample data
	 * (Dynamic analysis of this one gives lots of complicated results.)
	 */
	@Test
	public void test_Troj_Zbot_ITY() {
		System.out.println();
		System.out.println("STIXExtractor.SophosExtractorTest.test_Troj_Zbot_ITY()");
		
		String entryName = "Troj~Zbot-ITY";
		boolean localMode = true;
		String summary, details;
		
		try {
			Map<String,String> pageContent = loadContent(entryName, localMode);
			summary = pageContent.get("summary");
			details = pageContent.get("details");
			
			SophosExtractor sophosExtractor = new SophosExtractor(summary, details);
			STIXPackage receivedPackage = sophosExtractor.getStixPackage();			

			System.out.println("Validating StixPackage");					
			assertTrue(sophosExtractor.validate(receivedPackage));
			
			Document doc = Jsoup.parse(receivedPackage.toXMLString(), "", Parser.xmlParser());	
	
			Element indicator = doc.select("stix|Indicator").first();	
			System.out.println("Testing Title");
			assertEquals(indicator.select("ttp|Title").text(), "Malware");
			System.out.println("Testing Names");
			Elements names = doc.select("ttp|Name");
			List<String> nameList = new ArrayList<String>();
			for (Element name : names) {
				nameList.add(name.text());
			}														
			assertTrue(nameList.contains("Troj/Zbot-ITY"));
			assertTrue(nameList.contains("Gen:Variant.Graftor.150885"));
			System.out.println("Testing Type");
			assertEquals(indicator.select("ttp|Type").text(), "Trojan");
			System.out.println("Testing Description");				
			assertEquals(indicator.select("ttp|Description").text(), "Troj/Zbot-ITY");
			System.out.println("Testing Platform");
			assertEquals(indicator.select("ttp|Targeted_Systems").text(), "Windows");
			System.out.println("Testing Source");
			assertEquals(indicator.select("stixCommon|Name").text(), "Sophos");
			System.out.println("Testing FilesCreated");
			Elements files = doc.select("cybox|Action:has(cybox|Description:contains(Created files))").first().select("FileObj|File_Name");
			List<String> fileList = new ArrayList<String>();
			for (Element file : files) {
				fileList.add(file.text());
			}
			assertTrue(fileList.contains("c:\\Documents and Settings\\test user\\Application Data\\Poce\\anyn.ezo"));
			assertTrue(fileList.contains("c:\\Documents and Settings\\test user\\Application Data\\Veufno\\buerx.exe"));

			System.out.println("Testing FilesModified");
			fileList = new ArrayList<String>();
			files = doc.select("cybox|Action:has(cybox|Description:contains(Modified files))").first().select("FileObj|File_Name");
			for (Element file : files) {
				fileList.add(file.text());
			}
			assertTrue(fileList.contains("%PROFILE%\\Local Settings\\Application Data\\Identities\\{E2564744-A8ED-497D-924B-A548B20CA034}\\Microsoft\\Outlook Express\\Folders.dbx"));
			assertTrue(fileList.contains("%PROFILE%\\Local Settings\\Application Data\\Identities\\{E2564744-A8ED-497D-924B-A548B20CA034}\\Microsoft\\Outlook Express\\Inbox.dbx"));
			assertTrue(fileList.contains("%PROFILE%\\Local Settings\\Application Data\\Identities\\{E2564744-A8ED-497D-924B-A548B20CA034}\\Microsoft\\Outlook Express\\Offline.dbx"));

			System.out.println("Testing RegistryKeysCreated");
			Elements keys = doc.select("cybox|Action:has(cybox|Description:contains(Created registry keys))").first().select("WinRegistryKeyObj|Key");
			List<String> keyList = new ArrayList<String>();
			for (Element key : keys) {
				keyList.add(key.text());
			}
			assertTrue(keyList.contains("HKCU\\Identities"));
			assertTrue(keyList.contains("HKCU\\Software\\Microsoft\\Dyxol"));
			assertTrue(keyList.contains("HKCU\\Software\\Microsoft\\Internet Explorer\\Privacy"));
			assertTrue(keyList.contains("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"));
			
			System.out.println("Testing RegistryKeysModified");
			keys = doc.select("cybox|Action:has(cybox|Description:contains(Modified registry keys))").first().select("WinRegistryKeyObj|Key");
			keyList = new ArrayList<String>();
			for (Element key : keys) {
				keyList.add(key.text());
			}
			assertTrue(keyList.contains("HKCU\\Identities\\{E2564744-A8ED-497D-924B-A548B20CA034}\\Software\\Microsoft\\Outlook Express\\5.0"));
			assertTrue(keyList.contains("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\0"));
			assertTrue(keyList.contains("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\1"));
			assertTrue(keyList.contains("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\2"));
			assertTrue(keyList.contains("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\4"));
			assertTrue(keyList.contains("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\UnreadMail\\user@example.com"));
			
			System.out.println("Testing ProcessesCreated");
			keys = doc.select("cybox|Action:has(cybox|Description:contains(Created processes))").first().select("ProcessObj|Name");
			List<String> processList = new ArrayList<String>();
			for (Element key : keys) {
				processList.add(key.text());
			}
			assertTrue(processList.contains("c:\\Documents and Settings\\test user\\application data\\veufno\\buerx.exe"));
			assertTrue(processList.contains("c:\\windows\\system32\\cmd.exe"));
			assertTrue(processList.contains("c:\\windows\\system32\\hostname.exe"));
			assertTrue(processList.contains("c:\\windows\\system32\\ipconfig.exe"));
			assertTrue(processList.contains("c:\\windows\\system32\\tasklist.exe"));

			System.out.println("Testing FileTypes + Hashed");
			Elements fileTypes = doc.select("cybox|Object:has(FileObj|File_Name:contains(Windows executable))").select("FileObj|File_Name");
			List<String> typeList = new ArrayList<String>();
			for (Element type : fileTypes) {
				typeList.add(type.text());
			}
			assertTrue(typeList.contains("Windows executable"));
			Elements md5Hashes = doc.select("cybox|Object:has(FileObj|File_Name:contains(Windows executable))")
					.select("cyboxCommon|Hash:has(cyboxCommon|Type:contains(MD5))").select("cyboxCommon|Simple_Hash_Value");
			List<String> md5List = new ArrayList<String>();
			for (Element md5 : md5Hashes) {
				md5List.add(md5.text());
			}
			assertTrue(md5List.contains("599990d8fa3d211b0b775d82dd939526"));
			assertTrue(md5List.contains("ca2fe00295a6255ced2778fb9f43146f"));

			Elements sha1Hashes = doc.select("cybox|Object:has(FileObj|File_Name:contains(Windows executable))")
					.select("cyboxCommon|Hash:has(cyboxCommon|Type:contains(SHA-1))").select("cyboxCommon|Simple_Hash_Value");
			List<String> sha1List = new ArrayList<String>();
			for (Element sha1 : sha1Hashes) {
				sha1List.add(sha1.text());
			}
			assertTrue(sha1List.contains("8bff3c73c92314a7d094a0d024cf57a722b0b198"));
			assertTrue(sha1List.contains("9017bd0da5f94f4ba899e5d990c8c4f4792d6876"));

			System.out.println("Testing URLsUsed");
			Elements urls = doc.select("ttp|Tool > cyboxCommon|Name");
			List<String> urlList = new ArrayList<String>();
			for (Element url : urls) {
				urlList.add(url.text());
			}
			assertTrue(urlList.contains("http://www.google.com/webhp"));
			assertTrue(urlList.contains("http://www.google.ie/webhp"));

			System.out.println("Testing Malware -> Address relation");
			indicator = doc.select("stix|Indicator").first();
			Elements idrefs = indicator.select("cybox|Observable[idref]");
			List<String> idrefList = new ArrayList<String>();
			List<String> addressList = new ArrayList<String>();
			for (Element idref : idrefs) {
				idrefList.add(idref.attr("idref"));
				Element address = doc.select("cybox|Observable[id = " + idref.attr("idref") + "]").first();
				addressList.add(address.select("cybox|Object > cybox|Description").first().text());
			}
			assertTrue(idrefList.size() == 3);
			assertTrue(addressList.contains("franciz-industries.biz, port 80"));
			assertTrue(addressList.contains("www.google.com, port 80"));
			assertTrue(addressList.contains("www.google.ie, port 80"));

			System.out.println();
			System.out.println("Testing Address:");
			Element address1 = doc.select("cybox|Observable:has(cybox|Object:has(cybox|Description:contains(franciz-industries.biz, port 80)))").first();
			System.out.println("Testing Title");
			assertEquals(address1.select("cybox|Title").text(), "Address");
			System.out.println("Testing Source");
			assertEquals(address1.select("cybox|Observable_Source > cyboxCommon|Information_Source_Type").text(), "Sophos");
			System.out.println("Testing Description");
			assertEquals(address1.select("cybox|Object > cybox|Description").text(), "franciz-industries.biz, port 80");
			System.out.println("Testing Address -> DNSName relation");
			String dnsId = address1.select("cybox|Related_Object").attr("idref");
			Element dns1 = doc.select("[id = " + dnsId + "]").first();
			assertEquals(dns1.select("URIObj|Value").text(), "franciz-industries.biz");
			System.out.println("Testing Address -> Port relation");
			String portId = address1.select("SocketAddressObj|Port").attr("object_reference");
			Element port = doc.select("[id = " + portId + "]").first();
			assertEquals(port.select("PortObj|Port_Value").text(), "80");

			System.out.println();
			System.out.println("Testing Address:");
			Element address2 = doc.select("cybox|Observable:has(cybox|Object:has(cybox|Description:contains(www.google.com, port 80)))").first();
			System.out.println("Testing Title");
			assertEquals(address2.select("cybox|Title").text(), "Address");
			System.out.println("Testing Source");
			assertEquals(address2.select("cybox|Observable_Source > cyboxCommon|Information_Source_Type").text(), "Sophos");
			System.out.println("Testing Description");
			assertEquals(address2.select("cybox|Object > cybox|Description").text(), "www.google.com, port 80");
			System.out.println("Testing Address -> DNSName relation");
			dnsId = address2.select("cybox|Related_Object").attr("idref");
			Element dns2 = doc.select("[id = " + dnsId + "]").first();
			assertEquals(dns2.select("URIObj|Value").text(), "www.google.com");
			System.out.println("Testing Address -> Port relation");
			portId = address2.select("SocketAddressObj|Port").attr("object_reference");
			port = doc.select("[id = " + portId + "]").first();
			assertEquals(port.select("PortObj|Port_Value").text(), "80");
			
			System.out.println();
			System.out.println("Testing Address:");
			Element address3 = doc.select("cybox|Observable:has(cybox|Object:has(cybox|Description:contains(www.google.ie, port 80)))").first();
			System.out.println("Testing Title");
			assertEquals(address3.select("cybox|Title").text(), "Address");
			System.out.println("Testing Source");
			assertEquals(address3.select("cybox|Observable_Source > cyboxCommon|Information_Source_Type").text(), "Sophos");
			System.out.println("Testing Description");
			assertEquals(address3.select("cybox|Object > cybox|Description").text(), "www.google.ie, port 80");
			System.out.println("Testing Address -> DNSName relation");
			dnsId = address3.select("cybox|Related_Object").attr("idref");
			Element dns3 = doc.select("[id = " + dnsId + "]").first();
			assertEquals(dns3.select("URIObj|Value").text(), "www.google.ie");
			System.out.println("Testing Address -> Port relation");
			portId = address3.select("SocketAddressObj|Port").attr("object_reference");
			port = doc.select("[id = " + portId + "]").first();
			assertEquals(port.select("PortObj|Port_Value").text(), "80");

			System.out.println();
			System.out.println("Testing Port");
			System.out.println("Testing Title");
			assertEquals(port.select("cybox|Title").text(), "Port");
			System.out.println("Testing Source");
			assertEquals(port.select("cyboxCommon|Information_Source_Type").text(), "Sophos");
			System.out.println("Testing Port value");
			assertEquals(port.select("PortObj|Port_Value").text(), "80");
			System.out.println("Testing Description");
			assertEquals(port.select("cybox|Description").text(), "80");

			System.out.println();
			System.out.println("Testing DNSName");
			System.out.println("Testing Title");
			assertEquals(dns1.select("cybox|title").text(), "DNSName");
			System.out.println("Testing Name");
			assertEquals(dns1.select("whoisobj|domain_name > uriobj|value").text(), "franciz-industries.biz");
			System.out.println("Testing Description");
			assertEquals(dns1.select("cybox|description").text(), "franciz-industries.biz");
			System.out.println("Testing Source");
			assertEquals(dns1.select("cyboxcommon|information_source_type").text(), "Sophos");
			
			System.out.println();
			System.out.println("Testing DNSName");
			System.out.println("Testing Title");
			assertEquals(dns2.select("cybox|title").text(), "DNSName");
			System.out.println("Testing Name");
			assertEquals(dns2.select("whoisobj|domain_name > uriobj|value").text(), "www.google.com");
			System.out.println("Testing Description");
			assertEquals(dns2.select("cybox|description").text(), "www.google.com");
			System.out.println("Testing Source");
			assertEquals(dns2.select("cyboxcommon|information_source_type").text(), "Sophos");
			
			System.out.println();
			System.out.println("Testing DNSName");
			System.out.println("Testing Title");
			assertEquals(dns3.select("cybox|title").text(), "DNSName");
			System.out.println("Testing Name");
			assertEquals(dns3.select("whoisobj|domain_name > uriobj|value").text(), "www.google.ie");
			System.out.println("Testing Description");
			assertEquals(dns3.select("cybox|description").text(), "www.google.ie");
			System.out.println("Testing Source");
			assertEquals(dns3.select("cyboxcommon|information_source_type").text(), "Sophos");


		} catch (IOException e) {
			e.printStackTrace();
			fail("IOException");
		} catch (Exception e) {
			e.printStackTrace();
			fail("Exception");
		}
	}
	
	/**
	 * Test with "Troj~Zbot-AAA" sample data
	 * (Similar to above, but with less detailed results.)
	 */
	@Test
	public void test_Troj_Zbot_AAA() {
		System.out.println();
		System.out.println("STIXExtractor.SophosExtractorTest.test_Troj_Zbot_AAA()");
		String entryName = "Troj~Zbot-AAA";
		boolean localMode = true;
		String summary, details;
		
		try {
			Map<String,String> pageContent = loadContent(entryName, localMode);
			summary = pageContent.get("summary");
			details = pageContent.get("details");
			
			SophosExtractor sophosExtractor = new SophosExtractor(summary, details);
			STIXPackage receivedPackage = sophosExtractor.getStixPackage();
			
			System.out.println("Validating StixPackage");					
			assertTrue(sophosExtractor.validate(receivedPackage));
			
			Document doc = Jsoup.parse(receivedPackage.toXMLString(), "", Parser.xmlParser());	
	
			Element indicator = doc.select("stix|Indicator").first();	
			System.out.println("Testing Title");
			assertEquals(indicator.select("ttp|Title").text(), "Malware");
			System.out.println("Testing Names");
			Elements names = doc.select("ttp|Name");
			List<String> nameList = new ArrayList<String>();
			for (Element name : names) {
				nameList.add(name.text());
			}														
			assertTrue(nameList.contains("TR/Spy.ZBot.aput"));
			assertTrue(nameList.contains("Troj/Zbot-AAA"));
			assertTrue(nameList.contains("Trojan-Spy.Win32.Zbot.aput"));
			System.out.println("Testing Type");
			assertEquals(indicator.select("ttp|Type").text(), "Trojan");
			System.out.println("Testing Description");				
			assertEquals(indicator.select("ttp|Description").text(), "Troj/Zbot-AAA");
			System.out.println("Testing Platform");
			assertEquals(indicator.select("ttp|Targeted_Systems").text(), "Windows");
			System.out.println("Testing Source");
			assertEquals(indicator.select("stixCommon|Name").text(), "Sophos");
			System.out.println("Testing FilesCreated");
			Elements files = doc.select("cybox|Action:has(cybox|Description:contains(Created files))").first().select("FileObj|File_Name");
			List<String> fileList = new ArrayList<String>();
			for (Element file : files) {
				fileList.add(file.text());
			}
			assertTrue(fileList.size() == 1);
			assertTrue(fileList.contains("c:\\Documents and Settings\\test user\\Application Data\\Neceq\\esbo.exe"));
			
			System.out.println("Testing ProcessesCreated");
			Elements processes = doc.select("cybox|Action:has(cybox|Description:contains(Created processes))").first().select("ProcessObj|Name");
			List<String> processList = new ArrayList<String>();
			for (Element process : processes) {
				processList.add(process.text());
			}
			assertTrue(processList.size() == 1);
			assertTrue(processList.contains("c:\\windows\\system32\\cmd.exe"));
			
			System.out.println("Testing FileTypes + Hashed");
			Elements fileTypes = doc.select("cybox|Object:has(FileObj|File_Name)").select("FileObj|File_Name");
			List<String> typeList = new ArrayList<String>();
			for (Element type : fileTypes) {
				typeList.add(type.text());
			}
			assertTrue(typeList.contains("application/x-ms-dos-executable"));

			Elements md5Hashes = doc.select("cyboxCommon|Hash:has(cyboxCommon|Type:contains(MD5))");
			List<String> md5List = new ArrayList<String>();
			for (Element md5 : md5Hashes) {
				md5List.add(md5.select("cyboxCommon|Simple_Hash_Value").text());
			}
			assertTrue(md5List.contains("15eabc798ddf5542afec25946a00e987"));
			assertTrue(md5List.contains("c4e28e07ebb3a69fd165977f0331f1c5"));
			assertTrue(md5List.contains("d9dfa48afeb08f6e67fb8b2254a76870"));

			Elements sha1Hashes = doc.select("cyboxCommon|Hash:has(cyboxCommon|Type:contains(SHA-1))");
			List<String> sha1List = new ArrayList<String>();
			for (Element sha1 : sha1Hashes) {
				sha1List.add(sha1.select("cyboxCommon|Simple_Hash_Value").text());
			}
			assertTrue(sha1List.contains("5d012753322151c9d24bf45b98c35336225f383f"));
			assertTrue(sha1List.contains("b1005a9483866a45046a9b9d9bea09d39b29dcde"));
			assertTrue(sha1List.contains("b76ad9b1c6e01e41b8e05ab9be0617fff06fad98"));



		} catch (IOException e) {
			e.printStackTrace();
			fail("IOException");
		} catch (Exception e) {
			e.printStackTrace();
			fail("Exception");
		}
	}

	/**
	 * Test with "Troj~Weelsof-FG" sample data
	 * (Similar structure, only one sample shown, somewhat different fields included/excluded)
	 */
	@Test
	public void test_Troj_Weelsof_FG() {
		System.out.println();
		System.out.println("STIXExtractor.SophosExtractorTest.test_Troj_Weelsof_FG()");

		String entryName = "Troj~Weelsof-FG";
		boolean localMode = true;
		String summary, details;

		try {
			Map<String,String> pageContent = loadContent(entryName, localMode);
			summary = pageContent.get("summary");
			details = pageContent.get("details");

			SophosExtractor sophosExtractor = new SophosExtractor(summary, details);
			STIXPackage receivedPackage = sophosExtractor.getStixPackage();

			System.out.println("Validating StixPackage");					
			assertTrue(sophosExtractor.validate(receivedPackage));

			Document doc = Jsoup.parse(receivedPackage.toXMLString(), "", Parser.xmlParser());	

			Element indicator = doc.select("stix|Indicator").first();	
			System.out.println("Testing Title");
			assertEquals(indicator.select("ttp|Title").text(), "Malware");
			System.out.println("Testing Names");
			Elements names = doc.select("ttp|Name");
			List<String> nameList = new ArrayList<String>();
			for (Element name : names) {
				nameList.add(name.text());
			}														
			assertTrue(nameList.contains("TR/Crypt.XPACK.Gen7"));
			assertTrue(nameList.contains("Troj/Weelsof-FG"));

			System.out.println("Testing Type");
			assertEquals(indicator.select("ttp|Type").text(), "Trojan");
			System.out.println("Testing Description");				
			assertEquals(indicator.select("ttp|Description").text(), "Troj/Weelsof-FG");
			System.out.println("Testing Platform");
			assertEquals(indicator.select("ttp|Targeted_Systems").text(), "Windows");
			System.out.println("Testing Source");
			assertEquals(indicator.select("stixCommon|Name").text(), "Sophos");
			System.out.println("Testing FilesCreated");
			Elements files = doc.select("cybox|Action:has(cybox|Description:contains(Created files))").first().select("FileObj|File_Name");
			List<String> fileList = new ArrayList<String>();
			for (Element file : files) {
				fileList.add(file.text());
			}
			assertTrue(fileList.size() == 1);
			assertTrue(fileList.contains("c:\\Documents and Settings\\test user\\Local Settings\\Application Data\\nfdenoin.exe"));
			
			System.out.println("Testing ProcessesCreated");
			Elements processes = doc.select("cybox|Action:has(cybox|Description:contains(Created processes))").first().select("ProcessObj|Name");
			List<String> processList = new ArrayList<String>();
			for (Element process : processes) {
				processList.add(process.text());
			}
			assertTrue(processList.size() == 1);
			assertTrue(processList.contains("c:\\windows\\system32\\svchost.exe"));
			
			System.out.println("Testing RegistryKeysCreated");
			Elements keys = doc.select("cybox|Action:has(cybox|Description:contains(Created registry keys))").first().select("WinRegistryKeyObj|Key");
			List<String> keyList = new ArrayList<String>();
			for (Element key : keys) {
				keyList.add(key.text());
			}
			assertTrue(keyList.contains("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"));
			assertTrue(keyList.contains("HKCU\\Software\\fopnellh"));

			System.out.println("Testing FileTypes + Hashed");
			Elements fileTypes = doc.select("FileObj|File_Name");
			List<String> typeList = new ArrayList<String>();
			for (Element type : fileTypes) {
				typeList.add(type.text());
			}
			assertTrue(typeList.contains("application/x-ms-dos-executable"));
			
			Elements md5Hashes = doc.select("cyboxCommon|Hash:has(cyboxCommon|Type:contains(MD5))");
			List<String> md5List = new ArrayList<String>();
			for (Element md5 : md5Hashes) {
				md5List.add(md5.select("cyboxCommon|Simple_Hash_Value").text());
			}
			assertTrue(md5List.contains("cc3223eca31b00692fa49e63ac88139b"));
			
			Elements sha1Hashes = doc.select("cyboxCommon|Hash:has(cyboxCommon|Type:contains(SHA-1))");
			List<String> sha1List = new ArrayList<String>();
			for (Element sha1 : sha1Hashes) {
				sha1List.add(sha1.select("cyboxCommon|Simple_Hash_Value").text());
			}
			assertTrue(sha1List.contains("b2a166c4d67f324a6ae87e142040f932ccbb596d"));

			System.out.println("Testing Malware -> Address relation");
			indicator = doc.select("stix|Indicator").first();
			Elements idrefs = indicator.select("cybox|Observable[idref]");
			List<String> idrefList = new ArrayList<String>();
			List<String> addressList = new ArrayList<String>();
			for (Element idref : idrefs) {
				idrefList.add(idref.attr("idref"));
				Element address = doc.select("cybox|Observable[id = " + idref.attr("idref") + "]").first();
				addressList.add(address.select("cybox|Object > cybox|Description").first().text());
			}
			assertTrue(idrefList.size() == 5);
			assertTrue(addressList.contains("176.123.0.160, port 8080"));
			assertTrue(addressList.contains("195.5.208.87, port 8080"));
			assertTrue(addressList.contains("195.65.173.133, port 8080"));
			assertTrue(addressList.contains("222.124.143.12, port 8080"));
			assertTrue(addressList.contains("46.105.117.13, port 8080"));

			System.out.println();
			System.out.println("Testing Address:");
			Element address = doc.select("cybox|Observable:has(cybox|Object:has(cybox|Description:contains(176.123.0.160, port 8080)))").first();
			System.out.println("Testing Title");
			assertEquals(address.select("cybox|Title").text(), "Address");
			System.out.println("Testing Source");
			assertEquals(address.select("cybox|Observable_Source > cyboxCommon|Information_Source_Type").text(), "Sophos");
			System.out.println("Testing Description");
			assertEquals(address.select("cybox|Object > cybox|Description").text(), "176.123.0.160, port 8080");

			System.out.println("Testing Address -> IP relation");
			String ipId = address.select("SocketAddressObj|IP_Address").attr("object_reference");
			Element ip1 = doc.select("[id = " + ipId + "]").first();
			assertEquals(ip1.select("AddressObj|Address_Value").text(), "176.123.0.160");

			System.out.println("Testing Address -> Port relation");
			String portId = address.select("SocketAddressObj|Port").attr("object_reference");
			Element port1 = doc.select("[id = " + portId + "]").first();
			assertEquals(port1.select("PortObj|Port_Value").text(), "8080");

			System.out.println();
			System.out.println("Testing Address:");
			address = doc.select("cybox|Observable:has(cybox|Object:has(cybox|Description:contains(195.5.208.87, port 8080)))").first();
			System.out.println("Testing Title");
			assertEquals(address.select("cybox|Title").text(), "Address");
			System.out.println("Testing Source");
			assertEquals(address.select("cybox|Observable_Source > cyboxCommon|Information_Source_Type").text(), "Sophos");
			System.out.println("Testing Description");
			assertEquals(address.select("cybox|Object > cybox|Description").text(), "195.5.208.87, port 8080");

			System.out.println("Testing Address -> IP relation");
			ipId = address.select("SocketAddressObj|IP_Address").attr("object_reference");
			Element ip2 = doc.select("[id = " + ipId + "]").first();
			assertEquals(ip2.select("AddressObj|Address_Value").text(), "195.5.208.87");

			System.out.println("Testing Address -> Port relation");
			portId = address.select("SocketAddressObj|Port").attr("object_reference");
			Element port2 = doc.select("[id = " + portId + "]").first();
			assertEquals(port2.select("PortObj|Port_Value").text(), "8080");

			System.out.println();
			System.out.println("Testing Address:");
			address = doc.select("cybox|Observable:has(cybox|Object:has(cybox|Description:contains(195.65.173.133, port 8080)))").first();
			System.out.println("Testing Title");
			assertEquals(address.select("cybox|Title").text(), "Address");
			System.out.println("Testing Source");
			assertEquals(address.select("cybox|Observable_Source > cyboxCommon|Information_Source_Type").text(), "Sophos");
			System.out.println("Testing Description");
			assertEquals(address.select("cybox|Object > cybox|Description").text(), "195.65.173.133, port 8080");

			System.out.println("Testing Address -> IP relation");
			ipId = address.select("SocketAddressObj|IP_Address").attr("object_reference");
			Element ip3 = doc.select("[id = " + ipId + "]").first();
			assertEquals(ip3.select("AddressObj|Address_Value").text(), "195.65.173.133");

			System.out.println("Testing Address -> Port relation");
			portId = address.select("SocketAddressObj|Port").attr("object_reference");
			Element port3 = doc.select("[id = " + portId + "]").first();
			assertEquals(port3.select("PortObj|Port_Value").text(), "8080");
			
			System.out.println();
			System.out.println("Testing Address:");
			address = doc.select("cybox|Observable:has(cybox|Object:has(cybox|Description:contains(222.124.143.12, port 8080)))").first();
			System.out.println("Testing Title");
			assertEquals(address.select("cybox|Title").text(), "Address");
			System.out.println("Testing Source");
			assertEquals(address.select("cybox|Observable_Source > cyboxCommon|Information_Source_Type").text(), "Sophos");
			System.out.println("Testing Description");
			assertEquals(address.select("cybox|Object > cybox|Description").text(), "222.124.143.12, port 8080");

			System.out.println("Testing Address -> IP relation");
			ipId = address.select("SocketAddressObj|IP_Address").attr("object_reference");
			Element ip4 = doc.select("[id = " + ipId + "]").first();
			assertEquals(ip4.select("AddressObj|Address_Value").text(), "222.124.143.12");

			System.out.println("Testing Address -> Port relation");
			portId = address.select("SocketAddressObj|Port").attr("object_reference");
			Element port4 = doc.select("[id = " + portId + "]").first();
			assertEquals(port4.select("PortObj|Port_Value").text(), "8080");
			
			System.out.println();
			System.out.println("Testing Address:");
			address = doc.select("cybox|Observable:has(cybox|Object:has(cybox|Description:contains(46.105.117.13, port 8080)))").first();
			System.out.println("Testing Title");
			assertEquals(address.select("cybox|Title").text(), "Address");
			System.out.println("Testing Source");
			assertEquals(address.select("cybox|Observable_Source > cyboxCommon|Information_Source_Type").text(), "Sophos");
			System.out.println("Testing Description");
			assertEquals(address.select("cybox|Object > cybox|Description").text(), "46.105.117.13, port 8080");

			System.out.println("Testing Address -> IP relation");
			ipId = address.select("SocketAddressObj|IP_Address").attr("object_reference");
			Element ip5 = doc.select("[id = " + ipId + "]").first();
			assertEquals(ip5.select("AddressObj|Address_Value").text(), "46.105.117.13");

			System.out.println("Testing Address -> Port relation");
			portId = address.select("SocketAddressObj|Port").attr("object_reference");
			Element port5 = doc.select("[id = " + portId + "]").first();
			assertEquals(port5.select("PortObj|Port_Value").text(), "8080");
			
			System.out.println();
			System.out.println("Testing Port");
			System.out.println("Testing Title");
			assertEquals(port1.select("cybox|Title").text(), "Port");
			System.out.println("Testing Source");
			assertEquals(port1.select("cyboxCommon|Information_Source_Type").text(), "Sophos");
			System.out.println("Testing Port value");
			assertEquals(port1.select("PortObj|Port_Value").text(), "8080");
			System.out.println("Testing Description");
			assertEquals(port1.select("cybox|Description").text(), "8080");
			
			System.out.println();
			System.out.println("Testing Port");
			System.out.println("Testing Title");
			assertEquals(port2.select("cybox|Title").text(), "Port");
			System.out.println("Testing Source");
			assertEquals(port2.select("cyboxCommon|Information_Source_Type").text(), "Sophos");
			System.out.println("Testing Port value");
			assertEquals(port2.select("PortObj|Port_Value").text(), "8080");
			System.out.println("Testing Description");
			assertEquals(port2.select("cybox|Description").text(), "8080");
			
			System.out.println();
			System.out.println("Testing Port");
			System.out.println("Testing Title");
			assertEquals(port3.select("cybox|Title").text(), "Port");
			System.out.println("Testing Source");
			assertEquals(port3.select("cyboxCommon|Information_Source_Type").text(), "Sophos");
			System.out.println("Testing Port value");
			assertEquals(port3.select("PortObj|Port_Value").text(), "8080");
			System.out.println("Testing Description");
			assertEquals(port3.select("cybox|Description").text(), "8080");
			
			System.out.println();
			System.out.println("Testing Port");
			System.out.println("Testing Title");
			assertEquals(port4.select("cybox|Title").text(), "Port");
			System.out.println("Testing Source");
			assertEquals(port4.select("cyboxCommon|Information_Source_Type").text(), "Sophos");
			System.out.println("Testing Port value");
			assertEquals(port4.select("PortObj|Port_Value").text(), "8080");
			System.out.println("Testing Description");
			assertEquals(port4.select("cybox|Description").text(), "8080");
			
			System.out.println();
			System.out.println("Testing Port");
			System.out.println("Testing Title");
			assertEquals(port5.select("cybox|Title").text(), "Port");
			System.out.println("Testing Source");
			assertEquals(port5.select("cyboxCommon|Information_Source_Type").text(), "Sophos");
			System.out.println("Testing Port value");
			assertEquals(port5.select("PortObj|Port_Value").text(), "8080");
			System.out.println("Testing Description");
			assertEquals(port5.select("cybox|Description").text(), "8080");

			System.out.println();
			System.out.println("Testing IP content");
			System.out.println("Testing Title");
			assertEquals(ip1.select("cybox|Title").text(), "IP");
			System.out.println("Testing Source");
			assertEquals(ip1.select("cyboxCommon|Information_Source_Type").text(), "Sophos");
			System.out.println("Testing IP Long (ID)");
			assertEquals(ip1.select("cybox|Object").attr("id"), "stucco:ip-" + ipToLong("176.123.0.160"));
			System.out.println("Testing IP String");
			assertEquals(ip1.select("AddressObj|Address_Value").text(), "176.123.0.160");
			System.out.println("Testing Description");
			assertEquals(ip1.select("cybox|Description").text(), "176.123.0.160");

			System.out.println();
			System.out.println("Testing IP content");
			System.out.println("Testing Title");
			assertEquals(ip2.select("cybox|Title").text(), "IP");
			System.out.println("Testing Source");
			assertEquals(ip2.select("cyboxCommon|Information_Source_Type").text(), "Sophos");
			System.out.println("Testing IP Long (ID)");
			assertEquals(ip2.select("cybox|Object").attr("id"), "stucco:ip-" + ipToLong("195.5.208.87"));
			System.out.println("Testing IP String");
			assertEquals(ip2.select("AddressObj|Address_Value").text(), "195.5.208.87");
			System.out.println("Testing Description");
			assertEquals(ip2.select("cybox|Description").text(), "195.5.208.87");

			System.out.println();
			System.out.println("Testing IP content");
			System.out.println("Testing Title");
			assertEquals(ip3.select("cybox|Title").text(), "IP");
			System.out.println("Testing Source");
			assertEquals(ip3.select("cyboxCommon|Information_Source_Type").text(), "Sophos");
			System.out.println("Testing IP Long (ID)");
			assertEquals(ip3.select("cybox|Object").attr("id"), "stucco:ip-" + ipToLong("195.65.173.133"));
			System.out.println("Testing IP String");
			assertEquals(ip3.select("AddressObj|Address_Value").text(), "195.65.173.133");
			System.out.println("Testing Description");
			assertEquals(ip3.select("cybox|Description").text(), "195.65.173.133");
			
			System.out.println();
			System.out.println("Testing IP content");
			System.out.println("Testing Title");
			assertEquals(ip4.select("cybox|Title").text(), "IP");
			System.out.println("Testing Source");
			assertEquals(ip4.select("cyboxCommon|Information_Source_Type").text(), "Sophos");
			System.out.println("Testing IP Long (ID)");
			assertEquals(ip4.select("cybox|Object").attr("id"), "stucco:ip-" + ipToLong("222.124.143.12"));
			System.out.println("Testing IP String");
			assertEquals(ip4.select("AddressObj|Address_Value").text(), "222.124.143.12");
			System.out.println("Testing Description");
			assertEquals(ip4.select("cybox|Description").text(), "222.124.143.12");

			System.out.println();
			System.out.println("Testing IP content");
			System.out.println("Testing Title");
			assertEquals(ip5.select("cybox|Title").text(), "IP");
			System.out.println("Testing Source");
			assertEquals(ip5.select("cyboxCommon|Information_Source_Type").text(), "Sophos");
			System.out.println("Testing IP Long (ID)");
			assertEquals(ip5.select("cybox|Object").attr("id"), "stucco:ip-" + ipToLong("46.105.117.13"));
			System.out.println("Testing IP String");
			assertEquals(ip5.select("AddressObj|Address_Value").text(), "46.105.117.13");
			System.out.println("Testing Description");
			assertEquals(ip5.select("cybox|Description").text(), "46.105.117.13");
		
		} catch (IOException e) {
			e.printStackTrace();
			fail("IOException");
		} catch (Exception e) {
			e.printStackTrace();
			fail("Exception");
		}
	}
	
	
	/**
	 * Test with "Troj~MSIL-ACB" sample data
	 */
	@Test
	public void test_Troj_MSIL_ACB() {
		System.out.println();
		System.out.println("STIXExtractor.SophosExtractorTest.test_Troj_MSIL_ACB()");
		
		String entryName = "Troj~MSIL-ACB";
		boolean localMode = true;
		String summary, details;
		
		try {
			Map<String,String> pageContent = loadContent(entryName, localMode);
			summary = pageContent.get("summary");
			details = pageContent.get("details");
			
			SophosExtractor sophosExtractor = new SophosExtractor(summary, details);
			STIXPackage receivedPackage = sophosExtractor.getStixPackage();
			
			System.out.println("Validating StixPackage");					
			assertTrue(sophosExtractor.validate(receivedPackage));

			Document doc = Jsoup.parse(receivedPackage.toXMLString(), "", Parser.xmlParser());	

			Element indicator = doc.select("stix|Indicator").first();	
			System.out.println("Testing Title");
			assertEquals(indicator.select("ttp|Title").text(), "Malware");
			Elements names = doc.select("ttp|Name");
			List<String> nameList = new ArrayList<String>();
			for (Element name : names) {
				nameList.add(name.text());
			}														
			assertTrue(nameList.contains("TR/Dropper.MSIL.Gen8"));
			assertTrue(nameList.contains("Troj/MSIL-ACB"));

			System.out.println("Testing Type");
			assertEquals(indicator.select("ttp|Type").text(), "Trojan");
			System.out.println("Testing Description");				
			assertEquals(indicator.select("ttp|Description").text(), "Troj/MSIL-ACB");
			System.out.println("Testing Platform");
			assertEquals(indicator.select("ttp|Targeted_Systems").text(), "Windows");
			System.out.println("Testing Source");
			assertEquals(indicator.select("stixCommon|Name").text(), "Sophos");
			
			System.out.println("Testing FilesCreated");
			Elements files = doc.select("cybox|Action:has(cybox|Description:contains(Created files))").first().select("FileObj|File_Name");
			List<String> fileList = new ArrayList<String>();
			for (Element file : files) {
				fileList.add(file.text());
			}
			assertTrue(fileList.size() == 1);
			assertTrue(fileList.contains("c:\\Documents and Settings\\test user\\Local Settings\\Temp\\141781.bat"));
			
			System.out.println("Testing ProcessesCreated");
			Elements processes = doc.select("cybox|Action:has(cybox|Description:contains(Created processes))").first().select("ProcessObj|Name");
			List<String> processList = new ArrayList<String>();
			for (Element process : processes) {
				processList.add(process.text());
			}
			assertTrue(processList.size() == 1);
			assertTrue(processList.contains("c:\\windows\\system32\\cmd.exe"));
			
			System.out.println("Testing RegistryKeysCreated");
			Elements keys = doc.select("cybox|Action:has(cybox|Description:contains(Created registry keys))").first().select("WinRegistryKeyObj|Key");
			List<String> keyList = new ArrayList<String>();
			for (Element key : keys) {
				keyList.add(key.text());
			}
			assertTrue(keyList.size() == 1);
			assertTrue(keyList.contains("HKCU\\Software\\WinRAR"));
			
			System.out.println("Testing URLsUsed");
			Elements urls = doc.select("ttp|Tool > cyboxCommon|Name");
			List<String> urlList = new ArrayList<String>();
			for (Element url : urls) {
				urlList.add(url.text());
			}
			assertTrue(urlList.contains("http://riseandshine.favcc1.com/gate.php"));
			
			System.out.println("Testing FileTypes + Hashed");
			Elements fileTypes = doc.select("FileObj|File_Name");
			List<String> typeList = new ArrayList<String>();
			for (Element type : fileTypes) {
				typeList.add(type.text());
			}
			assertTrue(typeList.contains("application/x-ms-dos-executable"));
	
			Elements sha1Hashes = doc.select("cyboxCommon|Hash:has(cyboxCommon|Type:contains(SHA-1))");
			List<String> sha1List = new ArrayList<String>();
			for (Element sha1 : sha1Hashes) {
				sha1List.add(sha1.select("cyboxCommon|Simple_Hash_Value").text());
			}
			assertTrue(sha1List.size() == 1);
			assertTrue(sha1List.contains("4122be8402684403e480aaf5b37caf3b727d8077"));

			Elements md5Hashes = doc.select("cyboxCommon|Hash:has(cyboxCommon|Type:contains(MD5))");
			List<String> md5List = new ArrayList<String>();
			for (Element md5 : md5Hashes) {
				md5List.add(md5.select("cyboxCommon|Simple_Hash_Value").text());
			}
			assertTrue(md5List.size() == 1);
			assertTrue(md5List.contains("c5579ab457536d2fbd48e0a3bc6dc458"));

			System.out.println("Testing Malware -> Address relation");
			indicator = doc.select("stix|Indicator").first();
			Elements idrefs = indicator.select("cybox|Observable[idref]");
			List<String> idrefList = new ArrayList<String>();
			List<String> addressList = new ArrayList<String>();
			Element address = null;
			for (Element idref : idrefs) {
				idrefList.add(idref.attr("idref"));
				address = doc.select("cybox|Observable[id = " + idref.attr("idref") + "]").first();
				addressList.add(address.select("cybox|Object > cybox|Description").first().text());
			}
			assertTrue(idrefList.size() == 1);
			assertTrue(addressList.contains("riseandshine.favcc1.com, port 80"));
			
			System.out.println();
			System.out.println("Testing Address:");
			address = doc.select("cybox|Observable:has(cybox|Object:has(cybox|Description:contains(riseandshine.favcc1.com, port 80)))").first();
			System.out.println("Testing Title");
			assertEquals(address.select("cybox|Title").text(), "Address");
			System.out.println("Testing Source");
			assertEquals(address.select("cybox|Observable_Source > cyboxCommon|Information_Source_Type").text(), "Sophos");
			System.out.println("Testing Description");
			assertEquals(address.select("cybox|Object > cybox|Description").text(), "riseandshine.favcc1.com, port 80");
			
			System.out.println("Testing Address -> Port relation");
			String portId = address.select("SocketAddressObj|Port").attr("object_reference");
			Element port = doc.select("[id = " + portId + "]").first();
			assertEquals(port.select("PortObj|Port_Value").text(), "80");
			
			System.out.println("Testing Address -> DNSName relation");
			String dnsId = address.select("cybox|Related_Object").attr("idref");
			Element dns = doc.select("[id = " + dnsId + "]").first();
			assertEquals(dns.select("URIObj|Value").text(), "riseandshine.favcc1.com");

			System.out.println();
			System.out.println("Testing Port");
			System.out.println("Testing Title");
			assertEquals(port.select("cybox|Title").text(), "Port");
			System.out.println("Testing Source");
			assertEquals(port.select("cyboxCommon|Information_Source_Type").text(), "Sophos");
			System.out.println("Testing Port value");
			assertEquals(port.select("PortObj|Port_Value").text(), "80");
			System.out.println("Testing Description");
			assertEquals(port.select("cybox|Description").text(), "80");
			
			System.out.println();
			System.out.println("Testing DNSName");
			System.out.println("Testing Title");
			assertEquals(dns.select("cybox|title").text(), "DNSName");
			System.out.println("Testing Name");
			assertEquals(dns.select("whoisobj|domain_name > uriobj|value").text(), "riseandshine.favcc1.com");
			System.out.println("Testing Description");
			assertEquals(dns.select("cybox|description").text(), "riseandshine.favcc1.com");
			System.out.println("Testing Source");
			assertEquals(dns.select("cyboxcommon|information_source_type").text(), "Sophos");

		} catch (IOException e) {
			e.printStackTrace();
			fail("IOException");
		} catch (Exception e) {
			e.printStackTrace();
			fail("Exception");
		}
	}
}
