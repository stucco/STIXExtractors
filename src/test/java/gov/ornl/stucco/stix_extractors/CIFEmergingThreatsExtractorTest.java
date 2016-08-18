package gov.ornl.stucco.stix_extractors;

import java.util.List;
import java.util.ArrayList;

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
 * Unit test for CIFEmergingThreats Extractor.
 */
public class CIFEmergingThreatsExtractorTest {
	
	/**
	 * Test empty document
	 */
	@Test
	public void test_empty_document() {

		System.out.println();
		System.out.println("STIXExtractor.CIFEmergingThreatsExtractorTest.test_empty_document()");

		String cifInfo = "";

		CIFEmergingThreatsExtractor cifExtractor = new CIFEmergingThreatsExtractor(cifInfo);
		STIXPackage stixPackage = cifExtractor.getStixPackage();

		System.out.println("Testing that package is null");
		assertTrue(stixPackage == null);
	}

	/**
	 * Test one element
	 */
	@Test
	public void test_one_element() throws SAXException {

		System.out.println();
		System.out.println("STIXExtractor.CIF1d4ExtractorTest.test_one_element()");

		String cifInfo = "103.36.125.189";

		CIFEmergingThreatsExtractor cifExtractor = new CIFEmergingThreatsExtractor(cifInfo);
		STIXPackage stixPackage = cifExtractor.getStixPackage();
		
		System.out.println("Validating CIF Emerging Threats stixPackage");
		assertTrue(stixPackage.validate());

		Document doc = Jsoup.parse(stixPackage.toXMLString(), "", Parser.xmlParser());

		System.out.println();
		System.out.println("Testing Malware content:");
		Element malware = doc.select("stix|TTP").first();
		System.out.println("Testing Title");
		assertEquals(malware.select("stix|TTP > ttp|Title").text(), "Malware");
		System.out.println("Testing Source");
		assertEquals(malware.select("stixCommon|Identity > stixCommon|Name").text(), "rules.emergingthreats.net");
		System.out.println("Testing Type");
		assertEquals(malware.select("ttp|Type").text(), "Malware");
		System.out.println("Testing Name");
		assertEquals(malware.select("ttp|Name").text(), "Malware");
		System.out.println("Testing Description");
		assertEquals(malware.select("ttp|Description").text(), "Malware");
		System.out.println("Testing Malware -> IP relation");
		Elements ipId = malware.select("cybox|Observable");
		List<String> ipList = new ArrayList<String>();
		for (Element ip : ipId) {
			String id = ip.attr("idref");
			ip = doc.select("[id = " + id + "]").first();
			ipList.add(ip.select("AddressObj|Address_Value").text());
		}
		assertTrue(ipList.contains("103.36.125.189"));


		Element element = doc.select("cybox|Observable").first();
		
		System.out.println();
		System.out.println("Testing Title");
		assertEquals(element.select("cybox|Title").text(), "IP");
	//	System.out.println("Testing Keywords (Tags)");
	//	assertEquals(element.select("cybox|Keyword").text(), "Malware");
		System.out.println("Testing Source");
		assertEquals(element.select("cyboxCommon|Information_Source_Type").text(), "rules.emergingthreats.net");
		System.out.println("Testing IP Long (ID)");
		assertEquals(element.select("cybox|Object").attr("id"), "stucco:ip-1730444733");
		System.out.println("Testing IP String");
		assertEquals(element.select("AddressObj|Address_Value").text(), "103.36.125.189");
		System.out.println("Testing Description");
		assertEquals(element.select("cybox|Description").text(), "103.36.125.189");
	}

	/**
	 * Test four elements
	 */
	@Test
	public void test_four_elements() throws SAXException {

		System.out.println();
		System.out.println("STIXExtractor.CIFEmergingThreatsExtractorTest.test_four_elements()");

		String cifInfo = 
			"112.120.48.179\n" + 
			"113.195.145.12\n" +
			"113.195.145.70\n" + 
			"113.195.145.80";

		CIFEmergingThreatsExtractor cifExtractor = new CIFEmergingThreatsExtractor(cifInfo);
		STIXPackage stixPackage = cifExtractor.getStixPackage();
		
		System.out.println("Validating CIF Emerging Threats stixPackage");
		assertTrue(stixPackage.validate());

		Document doc = Jsoup.parse(stixPackage.toXMLString(), "", Parser.xmlParser());
		
		System.out.println();
		System.out.println("Testing Malware content:");
		Element malware = doc.select("stix|TTP").first();
		System.out.println("Testing Title");
		assertEquals(malware.select("stix|TTP > ttp|Title").text(), "Malware");
		System.out.println("Testing Source");
		assertEquals(malware.select("stixCommon|Identity > stixCommon|Name").text(), "rules.emergingthreats.net");
		System.out.println("Testing Type");
		assertEquals(malware.select("ttp|Type").text(), "Malware");
		System.out.println("Testing Name");
		assertEquals(malware.select("ttp|Name").text(), "Malware");
		System.out.println("Testing Description");
		assertEquals(malware.select("ttp|Description").text(), "Malware");
		System.out.println("Testing Malware -> IP relation");
		Elements ipId = malware.select("cybox|Observable");
		List<String> ipList = new ArrayList<String>();
		for (Element ip : ipId) {
			String id = ip.attr("idref");
			ip = doc.select("[id = " + id + "]").first();
			ipList.add(ip.select("AddressObj|Address_Value").text());
		}
		assertTrue(ipList.contains("112.120.48.179"));
		assertTrue(ipList.contains("113.195.145.12"));
		assertTrue(ipList.contains("113.195.145.70"));
		assertTrue(ipList.contains("113.195.145.80"));

		System.out.println();
		System.out.println("Testing 1st element:");
		Element element = doc.select("cybox|Observable:has(AddressObj|Address_Value:matches(^112.120.48.179\\Z))").first();
		
		System.out.println("Testing Title");
		assertEquals(element.select("cybox|Title").text(), "IP");
	//	System.out.println("Testing Keywords (Tags)");
	//	assertEquals(element.select("cybox|Keyword").text(), "Malware");
		System.out.println("Testing Source");
		assertEquals(element.select("cyboxCommon|Information_Source_Type").text(), "rules.emergingthreats.net");
		System.out.println("Testing IP Long (ID)");
		assertEquals(element.select("cybox|Object").attr("id"), "stucco:ip-1886924979");
		System.out.println("Testing IP String");
		assertEquals(element.select("AddressObj|Address_Value").text(), "112.120.48.179");
		System.out.println("Testing Description");
		assertEquals(element.select("cybox|Description").text(), "112.120.48.179");
		
		System.out.println();
		System.out.println("Testing 2nd element:");
		element = doc.select("cybox|Observable:has(AddressObj|Address_Value:matches(^113.195.145.12\\Z))").first();
		
		System.out.println("Testing Title");
		assertEquals(element.select("cybox|Title").text(), "IP");
	//	System.out.println("Testing Keywords (Tags)");
	//	assertEquals(element.select("cybox|Keyword").text(), "Malware");
		System.out.println("Testing Source");
		assertEquals(element.select("cyboxCommon|Information_Source_Type").text(), "rules.emergingthreats.net");
		System.out.println("Testing IP Long (ID)");
		assertEquals(element.select("cybox|Object").attr("id"), "stucco:ip-1908642060");
		System.out.println("Testing IP String");
		assertEquals(element.select("AddressObj|Address_Value").text(), "113.195.145.12");
		System.out.println("Testing Description");
		assertEquals(element.select("cybox|Description").text(), "113.195.145.12");
	
		System.out.println();
		System.out.println("Testing 3rd element:");
		element = doc.select("cybox|Observable:has(AddressObj|Address_Value:matches(^113.195.145.70\\Z))").first();
		
		System.out.println("Testing Title");
		assertEquals(element.select("cybox|Title").text(), "IP");
	//	System.out.println("Testing Keywords (Tags)");
	//	assertEquals(element.select("cybox|Keyword").text(), "Malware");
		System.out.println("Testing Source");
		assertEquals(element.select("cyboxCommon|Information_Source_Type").text(), "rules.emergingthreats.net");
		System.out.println("Testing IP Long (ID)");
		assertEquals(element.select("cybox|Object").attr("id"), "stucco:ip-1908642118");
		System.out.println("Testing IP String");
		assertEquals(element.select("AddressObj|Address_Value").text(), "113.195.145.70");
		System.out.println("Testing Description");
		assertEquals(element.select("cybox|Description").text(), "113.195.145.70");
		
		System.out.println();
		System.out.println("Testing 4rd element:");
		element = doc.select("cybox|Observable:has(AddressObj|Address_Value:matches(^113.195.145.80\\Z))").first();
		
		System.out.println("Testing Title");
		assertEquals(element.select("cybox|Title").text(), "IP");
	//	System.out.println("Testing Keywords (Tags)");
	//	assertEquals(element.select("cybox|Keyword").text(), "Malware");
		System.out.println("Testing Source");
		assertEquals(element.select("cyboxCommon|Information_Source_Type").text(), "rules.emergingthreats.net");
		System.out.println("Testing IP Long (ID)");
		assertEquals(element.select("cybox|Object").attr("id"), "stucco:ip-1908642128");
		System.out.println("Testing IP String");
		assertEquals(element.select("AddressObj|Address_Value").text(), "113.195.145.80");
		System.out.println("Testing Description");
		assertEquals(element.select("cybox|Description").text(), "113.195.145.80");
	}
}


