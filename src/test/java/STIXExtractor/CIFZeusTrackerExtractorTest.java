package STIXExtractor;

import java.util.List;
import java.util.ArrayList;

import org.jsoup.Jsoup;
import org.jsoup.parser.Parser;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import org.mitre.stix.stix_1.STIXPackage;

import org.junit.Test;

import static org.junit.Assert.*;

import STIXExtractor.CIFZeusTrackerExtractorTest;

/**
 * Unit test for CIFZeusTracker Extractor.
 */
public class CIFZeusTrackerExtractorTest {
	
	/**
	 * Test empty document
	 */
	@Test
	public void test_empty_document() {

		System.out.println();
		System.out.println("STIXExtractor.CIFZeusTrackerExtractorTest.test_empty_document()");

		String cifInfo = "";

		CIFZeusTrackerExtractor cifExtractor = new CIFZeusTrackerExtractor(cifInfo);
		STIXPackage stixPackage = cifExtractor.getStixPackage();

		System.out.println("Testing that package is null");
		assertTrue(stixPackage == null);
	}
	
	/**
	 * Test empty document with comment
	 */
	@Test
	public void test_empty_document_with_comment() {

		System.out.println();
		System.out.println("STIXExtractor.CIFZeusTrackerExtractorTest.test_empty_document_with_comment()");

		String cifInfo = 
			"##############################################################################\n" +
			"# abuse.ch ZeuS IP blocklist                                                 #\n" +
			"#                                                                            #\n" +
			"# For questions please refer to https://zeustracker.abuse.ch/blocklist.php   #\n" +
			"##############################################################################";

		CIFZeusTrackerExtractor cifExtractor = new CIFZeusTrackerExtractor(cifInfo);
		STIXPackage stixPackage = cifExtractor.getStixPackage();
		
		System.out.println("Testing that package is null");
		assertTrue(stixPackage == null);
	}
		
	/**
	 * Test one entry with comment
	 */
	@Test
	public void test_one_entry_with_comment() {

		System.out.println();
		System.out.println("STIXExtractor.CIFZeusTrackerExtractorTest.test_one_entry_with_comment()");

		String cifInfo = 
			"##############################################################################\n" +
			"# abuse.ch ZeuS IP blocklist                                                 #\n" +
			"#                                                                            #\n" +
			"# For questions please refer to https://zeustracker.abuse.ch/blocklist.php   #\n" +
			"##############################################################################\n" +
			"101.0.89.3";

		CIFZeusTrackerExtractor cifExtractor = new CIFZeusTrackerExtractor(cifInfo);
		STIXPackage stixPackage = cifExtractor.getStixPackage();

		System.out.println("Validating CIFZeusTracker stixPackage");
		assertTrue(cifExtractor.validate(stixPackage));
		
		Document doc = Jsoup.parse(stixPackage.toXMLString(), "", Parser.xmlParser());

		System.out.println();
		System.out.println("Testing Malware content:");
		Element malware = doc.select("stix|TTP").first();
		System.out.println("Testing Title");
		assertEquals(malware.select("ttp|Title").text(), "Malware");
		System.out.println("Testing Source");
		assertEquals(malware.select("stixCommon|Identity > stixCommon|Name").text(), "zeustracker.abuse.ch");
		System.out.println("Testing Type");
		assertEquals(malware.select("ttp|Type").text(), "Botnet");
		System.out.println("Testing Name");
		assertEquals(malware.select("ttp|Name").text(), "Botnet");
		System.out.println("Testing Description");
		assertEquals(malware.select("ttp|Description").text(), "Botnet");
		System.out.println("Testing Malware -> IP relation");
		Elements ipId = malware.select("cybox|Observable");
		List<String> ipList = new ArrayList<String>();
		for (Element ip : ipId) {
			String id = ip.attr("idref");
			ip = doc.select("[id = " + id + "]").first();
			ipList.add(ip.select("AddressObj|Address_Value").text());
		}
		assertTrue(ipList.contains("101.0.89.3"));
		
		Element element = doc.select("cybox|Observable").first();
		
		System.out.println("Testing Title");
		assertEquals(element.select("cybox|Title").text(), "IP");
		System.out.println("Testing Keywords (Tags)");
	//	assertEquals(element.select("cybox|Keyword").text(), "Botnet");
	//	System.out.println("Testing Source");
		assertEquals(element.select("cyboxCommon|Information_Source_Type").text(), "zeustracker.abuse.ch");
		System.out.println("Testing IP Long (ID)");
		assertEquals(element.select("cybox|Object").attr("id"), "stucco:ip-1694521603");
		System.out.println("Testing IP String");
		assertEquals(element.select("AddressObj|Address_Value").text(), "101.0.89.3");
		System.out.println("Testing Description");
		assertEquals(element.select("cybox|Description").text(), "101.0.89.3");
	}

	/**
	 * Test three entries with comment
	 */
	@Test
	public void test_three_entries_with_comment() {

		System.out.println();
		System.out.println("STIXExtractor.CIFZeusTrackerExtractorTest.test_three_entries_with_comment()");

		String cifInfo = 
			"##############################################################################\n" +
			"# abuse.ch ZeuS IP blocklist                                                 #\n" +
			"#                                                                            #\n" +
			"# For questions please refer to https://zeustracker.abuse.ch/blocklist.php   #\n" +
			"##############################################################################\n" +
			"101.0.89.3\n" +
			"103.19.89.118\n" +
			"103.230.84.239\n";

		CIFZeusTrackerExtractor cifExtractor = new CIFZeusTrackerExtractor(cifInfo);
		STIXPackage stixPackage = cifExtractor.getStixPackage();

		System.out.println("Validating CIFZeusTracker stixPackage");
		assertTrue(cifExtractor.validate(stixPackage));

		Document doc = Jsoup.parse(stixPackage.toXMLString(), "", Parser.xmlParser());
		
		System.out.println();
		System.out.println("Testing Malware content:");
		Element malware = doc.select("stix|TTP").first();
		System.out.println("Testing Title");
		assertEquals(malware.select("ttp|Title").text(), "Malware");
		System.out.println("Testing Source");
		assertEquals(malware.select("stixCommon|Identity > stixCommon|Name").text(), "zeustracker.abuse.ch");
		System.out.println("Testing Type");
		assertEquals(malware.select("ttp|Type").text(), "Botnet");
		System.out.println("Testing Name");
		assertEquals(malware.select("ttp|Name").text(), "Botnet");
		System.out.println("Testing Description");
		assertEquals(malware.select("ttp|Description").text(), "Botnet");
		System.out.println("Testing Malware -> IP relation");
		Elements ipId = malware.select("cybox|Observable");
		List<String> ipList = new ArrayList<String>();
		for (Element ip : ipId) {
			String id = ip.attr("idref");
			ip = doc.select("[id = " + id + "]").first();
			ipList.add(ip.select("AddressObj|Address_Value").text());
		}
		assertTrue(ipList.contains("101.0.89.3"));
		assertTrue(ipList.contains("103.19.89.118"));
		assertTrue(ipList.contains("103.230.84.239"));

		System.out.println();
		System.out.println("Testing 1st element:");
		Element element = doc.select("cybox|Observable:has(cybox|Object[id=stucco:ip-1694521603])").first();
		assertTrue(element.hasText());
		System.out.println("Testing Title");
		assertEquals(element.select("cybox|Title").text(), "IP");
	//	System.out.println("Testing Keywords (Tags)");
	//	assertEquals(element.select("cybox|Keyword").text(), "Botnet");
		System.out.println("Testing Source");
		assertEquals(element.select("cyboxCommon|Information_Source_Type").text(), "zeustracker.abuse.ch");
		System.out.println("Testing IP Long (ID)");
		assertEquals(element.select("cybox|Object").attr("id"), "stucco:ip-1694521603");
		System.out.println("Testing IP String");
		assertEquals(element.select("AddressObj|Address_Value").text(), "101.0.89.3");
		System.out.println("Testing Description");
		assertEquals(element.select("cybox|Description").text(), "101.0.89.3");
		
		System.out.println();
		System.out.println("Testing 2nd element:");
		element = doc.select("cybox|Observable:has(cybox|Object[id=stucco:ip-1729321334])").first();
		assertTrue(element.hasText());
		System.out.println("Testing Title");
		assertEquals(element.select("cybox|Title").text(), "IP");
	//	System.out.println("Testing Keywords (Tags)");
	//	assertEquals(element.select("cybox|Keyword").text(), "Botnet");
		System.out.println("Testing Source");
		assertEquals(element.select("cyboxCommon|Information_Source_Type").text(), "zeustracker.abuse.ch");
		System.out.println("Testing IP Long ID)");
		assertEquals(element.select("cybox|Object").attr("id"), "stucco:ip-1729321334");
		System.out.println("Testing IP String");
		assertEquals(element.select("AddressObj|Address_Value").text(), "103.19.89.118");
		System.out.println("Testing Description");
		assertEquals(element.select("cybox|Description").text(), "103.19.89.118");
		
		System.out.println();
		System.out.println("Testing 3rd element:");
		element = doc.select("cybox|Observable:has(cybox|Object[id=stucco:ip-1743148271])").first();
		assertTrue(element.hasText());
		System.out.println("Testing Title");
		assertEquals(element.select("cybox|Title").text(), "IP");
	//	System.out.println("Testing Keywords (Tags)");
	//	assertEquals(element.select("cybox|Keyword").text(), "Botnet");
		System.out.println("Testing Source");
		assertEquals(element.select("cyboxCommon|Information_Source_Type").text(), "zeustracker.abuse.ch");
		System.out.println("Testing IP Long (ID)");
		assertEquals(element.select("cybox|Object").attr("id"), "stucco:ip-1743148271");
		System.out.println("Testing IP String");
		assertEquals(element.select("AddressObj|Address_Value").text(), "103.230.84.239");
		System.out.println("Testing Description");
		assertEquals(element.select("cybox|Description").text(), "103.230.84.239");
	}
}


	



