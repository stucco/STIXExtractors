package STIXExtractor;

import java.util.List;
import java.util.ArrayList;

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

import STIXExtractor.FSecureExtractor;

import org.junit.Test;

import static org.junit.Assert.*;
	
import org.mitre.stix.stix_1.STIXPackage;

/**
 * Unit test for F-Secure extractor.
 */
public class FSecureExtractorTest {

	private String loadContent(String entryName, boolean localMode) throws IOException{
		String pageContent;
		String filePath = "./testData/f-secure/";
		Charset charset = Charset.defaultCharset();
		if(localMode){
			File infoFD = new File(filePath + entryName + ".shtml");
			pageContent = FileUtils.readFileToString(infoFD, charset);
		}
		else{
			URL u;
			try{
				u = new URL("http://www.f-secure.com/v-descs/"+entryName+".shtml");
				pageContent = IOUtils.toString(u);
			}catch(IOException e){ //some items have this prefix instead.  TODO: cleaner handling of this case.
				u = new URL("http://www.f-secure.com/sw-desc/"+entryName+".shtml");
				pageContent = IOUtils.toString(u);
			}
		}
		return pageContent;
	}
					
	/**
	 * Test with "application_w32_installbrain" sample data
	 */
	@Test
	public void test_application_w32_installbrain() {
		System.out.println();
		System.out.println("STIXExtractor.FSecureExtractorTest.test_application_w32_installbrain()");

		String entryName = "application_w32_installbrain";
		boolean localMode = true;
		String pageContent;
		
		try {
			pageContent = loadContent(entryName, localMode);
			
			FSecureExtractor fsecureExt = new FSecureExtractor(pageContent);
			STIXPackage fsecurePackage = fsecureExt.getStixPackage();

			System.out.println("Validating StixPackage");
			assertTrue(fsecureExt.validate(fsecurePackage));
			
			Document stix = Jsoup.parse(fsecurePackage.toXMLString(), "", Parser.xmlParser());

			Element malware = stix.select("stix|TTP").first();
			System.out.println("Testing Malware");
			System.out.println("Testing Title");
			assertEquals(malware.select(" > ttp|Title").text(), "Application:W32/InstallBrain");						
			System.out.println("Testing Platform");
			assertEquals(malware.select("ttp|Targeted_Systems").text(), "W32");						
			System.out.println("Testing Types");
			List<String> typesList = new ArrayList<String>();
			Elements types = malware.select("ttp|Type");
			for (Element type : types) {
				typesList.add(type.text());
			}
			assertTrue(typesList.contains("Spyware"));
			assertTrue(typesList.contains("Application"));
			System.out.println("Testing Description");
			assertEquals(malware.select("ttp|Malware_Instance > ttp|Description").text(), "InstallBrain is an updater service that runs in the background and periodically updates associates browser plug-ins and add-ons.");						
			System.out.println("Testing Details");
			assertEquals(malware.select("ttp|Attack_Pattern:has(ttp|Title:contains(Details)) > ttp|Description").text(), "InstallBrain is part of a software bundler program associated with various browser plug-ins and add-ons from the Perion Network software company. When installed, the application is essentially an updater service that will run in the background as 'ibsvc.exe' and periodically download and install updates for the associated browser components. The add-ons maintained by InstallBrain vary in function, but have reportedly silently reset the browser homepage and modified the search engine settings and/or search results. If the user elects to remove the components, the related InstallBrain program should also be uninstalled. As of early October 2013, some InstallBrain installers have shown code similarity to Trojan-Downloader:W32/Mevade; these installers are identified with the detection name Trojan:W32/Installbrain.[variant].");						
			System.out.println("Testing Source");
			assertEquals(malware.select("stixCommon|Name").text(), "F-Secure");						
			System.out.println("Testing Names");
			Elements names = malware.select("ttp|Name");
			List<String> namesList = new ArrayList<String>();
			for (Element name : names) {
				namesList.add(name.text());
			}
			assertTrue(namesList.contains("Application:W32/InstallBrain"));
			assertTrue(namesList.contains("Application:W32/InstallBrain.[variant]"));
			assertTrue(namesList.contains("Trojan:W32/InstallBrain.[variant]"));
			
			System.out.println("Testing COA");
			Element coa = stix.select("stix|Course_Of_Action > coa|Description").first();
			assertEquals(coa.text(), "F-Secure");
							
		} catch (IOException e) {
			e.printStackTrace();
			fail("IOException");
		} catch (Exception e) {
			e.printStackTrace();
			fail("Exception");
		}
	}

	/**
	 * Test with "backdoor_w32_havex" sample data
	 */
	@Test
	public void test_backdoor_w32_havex() {
		System.out.println();
		System.out.println("STIXExtractor.FSecureExtractorTest.test_application_w32_installbrain()");
		
		String entryName = "backdoor_w32_havex";
		boolean localMode = true;
		String pageContent;
		
		try {
			pageContent = loadContent(entryName, localMode);
			
			FSecureExtractor fsecureExt = new FSecureExtractor(pageContent);
			STIXPackage fsecurePackage = fsecureExt.getStixPackage();
		    	
			System.out.println("Validating StixPackage");
			assertTrue(fsecureExt.validate(fsecurePackage));
			
			Document stix = Jsoup.parse(fsecurePackage.toXMLString(), "", Parser.xmlParser());

			Element malware = stix.select("stix|TTP").first();
			System.out.println("Testing Malware");
			System.out.println("Testing Title");
			assertEquals(malware.select(" > ttp|Title").text(), "Backdoor:W32/Havex");						
			System.out.println("Testing Platform");
			assertEquals(malware.select("ttp|Targeted_Systems").text(), "W32");						
			System.out.println("Testing Types");
			List<String> typesList = new ArrayList<String>();
			Elements types = malware.select("ttp|Type");
			for (Element type : types) {
				typesList.add(type.text());
			}
			assertTrue(typesList.contains("Malware"));
			assertTrue(typesList.contains("Backdoor"));
			System.out.println("Testing Description");
			assertEquals(malware.select("ttp|Malware_Instance > ttp|Description").text(), "Havex is a Remote Access Tool (RAT) used in targeted attacks. Once present on a machine, it scans the system and connected resources for information that may be of use in later attacks; the collected data is forwarded to remote servers.");
			System.out.println("Testing Details");
			assertEquals(malware.select("ttp|Attack_Pattern:has(ttp|Title:contains(Details)) > ttp|Description").text(), "Havex is known to have been used in attacks targeted against various industrial sectors, particularly the energy sector. Variants seen circulating in the spring of 2014 were modified to target organizations involved in developing or using industrial applications or appliances.");
			System.out.println("Testing Behavior");
			assertEquals(malware.select("ttp|Attack_Pattern:has(ttp|Title:contains(Behavior)) > ttp|Description").text(), "Once the Havex malware has been delivered to the targeted users and installed on a machine, it scans the system and connected resources accessible over a network for information of interest. This information includes the presence of any Industrial Control Systems (ICS) or Supervisory Control And Data Acquisition (SCADA) systems present in the network. The collected data is then forwarded to compromised websites, which surreptitiously serve as remote command and control (C&C) servers. For more technical details, see: Labs Weblog: Havex Hunts for ICS/SCADA Systems");
			System.out.println("Testing Distribution");
			assertEquals(malware.select("ttp|Attack_Pattern:has(ttp|Title:contains(Distribution)) > ttp|Description").text(), "Havex is known to be distributed to targeted users through: Spam emails Exploit kits Trojanized installers planted on compromised vendor sites For the last distribution channel, compromised vendor sites that were identified were related to companies involved in the development of applications and appliances used in industrial settings. The affected companies are based in Germany, Switzerland and Belgium.");
			System.out.println("Testing Source");
			assertEquals(malware.select("stixCommon|Name").text(), "F-Secure");						
			System.out.println("Testing Names");
			Elements names = malware.select("ttp|Name");
			List<String> namesList = new ArrayList<String>();
			for (Element name : names) {
				namesList.add(name.text());
			}
			assertTrue(namesList.contains("Backdoor:W32/Havex"));
			
			System.out.println("Testing COA");
			Element coa = stix.select("stix|Course_Of_Action > coa|Description").first();
			assertEquals(coa.text(), "F-Secure");
							
		} catch (IOException e) {
			e.printStackTrace();
			fail("IOException");
		} catch (Exception e) {
			e.printStackTrace();
			fail("Exception");
		}
	}
	
	/**
	 * Test with "trojan_html_browlock" sample data
	 */
	@Test
	public void test_trojan_html_browlock() {
		System.out.println();
		System.out.println("STIXExtractor.FSecureExtractorTest.test_trojan_html_browlock()");
		String entryName = "trojan_html_browlock";
		boolean localMode = true;
		String pageContent;
		
		try {
			pageContent = loadContent(entryName, localMode);
			
			FSecureExtractor fsecureExt = new FSecureExtractor(pageContent);
			STIXPackage fsecurePackage = fsecureExt.getStixPackage();
		    	
			System.out.println("Validating StixPackage");
			assertTrue(fsecureExt.validate(fsecurePackage));
			
			Document stix = Jsoup.parse(fsecurePackage.toXMLString(), "", Parser.xmlParser());

			Element malware = stix.select("stix|TTP").first();
			System.out.println("Testing Malware");
			System.out.println("Testing Title");
			assertEquals(malware.select(" > ttp|Title").text(), "Trojan:HTML/Browlock");						
			System.out.println("Testing Platform");
			assertEquals(malware.select("ttp|Targeted_Systems").text(), "HTML");						
			System.out.println("Testing Types");
			List<String> typesList = new ArrayList<String>();
			Elements types = malware.select("ttp|Type");
			for (Element type : types) {
				typesList.add(type.text());
			}
			assertTrue(typesList.contains("Malware"));
			assertTrue(typesList.contains("Trojan"));
			System.out.println("Testing Description");
			assertEquals(malware.select("ttp|Malware_Instance > ttp|Description").text(), "Trojan:HTML/Browlock is ransomware that prevents users from accessing the infected machine's Desktop; it then demands payment, supposedly for either possession of illegal material or usage of illegal software.");
			System.out.println("Testing Details");
			assertEquals(malware.select("ttp|Attack_Pattern:has(ttp|Title:contains(Details)) > ttp|Description").text(), "Trojan:HTML/Browlock has been reported to target users in multiple countries, including the United States, the United Kingdom and Canada. Typically, it will display a 'lock screen' purportedly from a local or federal law enforcement authority, claiming that the machine has been locked and encrypted due to 'illegal activities'. A 'fine' is then demanded to restore the system. This malware was also covered in our Labs Weblog blogpost: Browlock Ransomware Targets New Countries A lock screen used by one Browlock variant is shown below: http://www.f-secure.com/weblog/archives/brow_uk.png");
			System.out.println("Testing Source");
			assertEquals(malware.select("stixCommon|Name").text(), "F-Secure");						
			System.out.println("Testing Names");
			Elements names = malware.select("ttp|Name");
			List<String> namesList = new ArrayList<String>();
			for (Element name : names) {
				namesList.add(name.text());
			}
			assertTrue(namesList.contains("Trojan:HTML/Browlock"));
			assertTrue(namesList.contains("Trojan:HTML/Browlock.[variant]"));
			
			System.out.println("Testing COA");
			Element coa = stix.select("stix|Course_Of_Action > coa|Description").first();
			assertEquals(coa.text(), "F-Secure");
							
		} catch (IOException e) {
			e.printStackTrace();
			fail("IOException");
		} catch (Exception e) {
			e.printStackTrace();
			fail("Exception");
		}
	}
	
	/**
	 * Test with "trojan_android_droidkungfu_c" sample data
	 */
	@Test
	public void test_trojan_android_droidkungfu_c() {
		System.out.println();
		System.out.println("STIXExtractor.FSecureExtractorTest.test_trojan_android_droidkungfu_c()");
		String entryName = "trojan_android_droidkungfu_c";
		boolean localMode = true;
		String pageContent;
		
		try {
			pageContent = loadContent(entryName, localMode);
			
			FSecureExtractor fsecureExt = new FSecureExtractor(pageContent);
			STIXPackage fsecurePackage = fsecureExt.getStixPackage();
		    	
			System.out.println("Validating StixPackage");
			assertTrue(fsecureExt.validate(fsecurePackage));
			
			Document stix = Jsoup.parse(fsecurePackage.toXMLString(), "", Parser.xmlParser());

			Element malware = stix.select("stix|TTP").first();
			System.out.println("Testing Malware");
			System.out.println("Testing Title");
			assertEquals(malware.select(" > ttp|Title").text(), "Trojan:Android/DroidKungFu.C");						
			System.out.println("Testing Platform");
			assertEquals(malware.select("ttp|Targeted_Systems").text(), "Android");						
			System.out.println("Testing Types");
			List<String> typesList = new ArrayList<String>();
			Elements types = malware.select("ttp|Type");
			for (Element type : types) {
				typesList.add(type.text());
			}
			assertTrue(typesList.contains("Malware"));
			assertTrue(typesList.contains("Trojan"));
			System.out.println("Testing Description");
			assertEquals(malware.select("ttp|Malware_Instance > ttp|Description").text(), "Trojan:Android/DroidKungFu.C forwards confidential details to a remote server.");
			System.out.println("Testing Details");
			assertEquals(malware.select("ttp|Attack_Pattern:has(ttp|Title:contains(Details)) > ttp|Description").text(), "Trojan:Android/DroidKungFu.C are distributed on unauthorized Android app sites as trojanized versions of legitimate applications.");
			System.out.println("Testing Source");
			assertEquals(malware.select("stixCommon|Name").text(), "F-Secure");						
			System.out.println("Testing Names");
			Elements names = malware.select("ttp|Name");
			List<String> namesList = new ArrayList<String>();
			for (Element name : names) {
				namesList.add(name.text());
			}
			assertTrue(namesList.contains("DroidKungFu"));
			assertTrue(namesList.contains("DroidKungFu.C"));
			assertTrue(namesList.contains("Trojan:Android/DroidKungFu.C"));
			
		} catch (IOException e) {
			e.printStackTrace();
			fail("IOException");
		} catch (Exception e) {
			e.printStackTrace();
			fail("Exception");
		}
	}
	
	/**
	 * Test with "trojan_bash_qhost_wb" sample data
	 */
	@Test
	public void test_trojan_bash_qhost_wb() {
		System.out.println();
		System.out.println("STIXExtractor.FSecureExtractorTest.test_trojan_bash_qhost_wb()");
		
		String entryName = "trojan_bash_qhost_wb";
		boolean localMode = true;
		String pageContent;
		
		try {
			pageContent = loadContent(entryName, localMode);
			
			FSecureExtractor fsecureExt = new FSecureExtractor(pageContent);
			STIXPackage fsecurePackage = fsecureExt.getStixPackage();
		    	
			System.out.println("Validating StixPackage");
			assertTrue(fsecureExt.validate(fsecurePackage));
			
			Document stix = Jsoup.parse(fsecurePackage.toXMLString(), "", Parser.xmlParser());

			Element malware = stix.select("stix|TTP").first();
			System.out.println("Testing Malware");
			System.out.println("Testing Title");
			assertEquals(malware.select(" > ttp|Title").text(), "Trojan:BASH/QHost.WB");						
			System.out.println("Testing Platform");
			assertEquals(malware.select("ttp|Targeted_Systems").text(), "BASH");						
			System.out.println("Testing Types");
			List<String> typesList = new ArrayList<String>();
			Elements types = malware.select("ttp|Type");
			for (Element type : types) {
				typesList.add(type.text());
			}
			assertTrue(typesList.contains("Malware"));
			assertTrue(typesList.contains("Trojan"));
			System.out.println("Testing Description");
			assertEquals(malware.select("ttp|Malware_Instance > ttp|Description").text(), "Trojan:BASH/QHost.WB hijacks web traffic by modifying the hosts file.");
			System.out.println("Testing Details");
			assertEquals(malware.select("ttp|Attack_Pattern:has(ttp|Title:contains(Details)) > ttp|Description").text(), "Trojan:BASH/QHost.WB poses as a FlashPlayer installer called FlashPlayer.pkg:");
			System.out.println("Testing Source");
			assertEquals(malware.select("stixCommon|Name").text(), "F-Secure");						
			System.out.println("Testing Names");
			Elements names = malware.select("ttp|Name");
			List<String> namesList = new ArrayList<String>();
			for (Element name : names) {
				namesList.add(name.text());
			}
			assertTrue(namesList.contains("BASH/QHost.WB"));
			assertTrue(namesList.contains("QHost"));
			assertTrue(namesList.contains("QHost.WB"));
			assertTrue(namesList.contains("Trojan:BASH/QHost.WB"));
							
		} catch (IOException e) {
			e.printStackTrace();
			fail("IOException");
		} catch (Exception e) {
			e.printStackTrace();
			fail("Exception");
		}
	}
}
