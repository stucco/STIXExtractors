package STIXExtractor;

import org.jsoup.Jsoup;
import org.jsoup.parser.Parser;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import org.mitre.stix.stix_1.STIXPackage;

import org.junit.Test;

import static org.junit.Assert.*;

import STIXExtractor.CpeExtractor;

/**
 * Unit test for Cpe Extractor.
 */
public class CpeExtractorTest	{
	
	/**
	 * Test empty document
	 */
	@Test
	public void test_empty_document()	{

		System.out.println("STIXExtractor.CpeExtractorTest.test_empty_document()");

		String cpeInfo = "";
		CpeExtractor cpeExtractor = new CpeExtractor(cpeInfo);
		STIXPackage stixPackage = cpeExtractor.getStixPackage();

		System.out.println("Testing that package is null");
		assertTrue(stixPackage == null);
	}

	/**
	 * Test one element
	 */
	@Test
	public void test_one_element()	{

		System.out.println("STIXExtractor.CpeExtractorTest.test_one_element()");

		String cpeInfo = 
			"<?xml version='1.0' encoding='UTF-8'?> " +
			"    <cpe-list xmlns:meta=\"http://scap.nist.gov/schema/cpe-dictionary-metadata/0.2\" xmlns:scap-core=\"http://scap.nist.gov/schema/scap-core/0.3\" xmlns:config=\"http://scap.nist.gov/schema/configuration/0.1\" xmlns=\"http://cpe.mitre.org/dictionary/2.0\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:ns6=\"http://scap.nist.gov/schema/scap-core/0.1\" xsi:schemaLocation=\"http://scap.nist.gov/schema/configuration/0.1 http://nvd.nist.gov/schema/configuration_0.1.xsd http://scap.nist.gov/schema/scap-core/0.3 http://nvd.nist.gov/schema/scap-core_0.3.xsd http://cpe.mitre.org/dictionary/2.0 http://cpe.mitre.org/files/cpe-dictionary_2.2.xsd http://scap.nist.gov/schema/scap-core/0.1 http://nvd.nist.gov/schema/scap-core_0.1.xsd http://scap.nist.gov/schema/cpe-dictionary-metadata/0.2 http://nvd.nist.gov/schema/cpe-dictionary-metadata_0.2.xsd\"> " +
			"      <generator> " +
			"        <product_name>National Vulnerability Database (NVD)</product_name> " +
			"        <product_version>2.18.0-SNAPSHOT (PRODUCTION)</product_version> " +
			"        <schema_version>2.2</schema_version> " +
			"        <timestamp>2013-03-19T03:50:00.109Z</timestamp> " +
			"      </generator> " +
			"      <cpe-item name=\"cpe:/a:1024cms:1024_cms:0.7\"> " +
			"        <title xml:lang=\"en-US\">1024cms.org 1024 CMS 0.7</title> " +
			"        <meta:item-metadata modification-date=\"2010-12-14T19:38:32.197Z\" status=\"DRAFT\" nvd-id=\"121218\"/> " +
			"      </cpe-item> " +
			"    </cpe-list> ";

		CpeExtractor cpeExtractor = new CpeExtractor(cpeInfo);
		STIXPackage stixPackage = cpeExtractor.getStixPackage();

		Document doc = Jsoup.parse(stixPackage.toXMLString(), "", Parser.xmlParser());
		Element element = doc.select("cybox|Observable").first();
		
		System.out.println();
		System.out.println("Testing Id");
		assertEquals(element.select("cybox|Object").attr("id"), "stucco:software-cpe:/a:1024cms:1024_cms:0.7");
		System.out.println("Testing Source");
		assertEquals(element.select("cyboxCommon|Information_Source_Type").text(), "CPE");
		System.out.println("Testing Title");
		assertEquals(element.select("cybox|Title").text(), "Software");
		System.out.println("Testing Description");
		assertEquals(element.select("cybox|Description").text(), "1024cms.org 1024 CMS 0.7");
		System.out.println("Testing Part");
		assertEquals(element.select("cyboxCommon|Property[name=Part]").text(), "/a");
		System.out.println("Testing Vendor");
		assertEquals(element.select("ProductObj|Vendor").text(), "1024cms");
		System.out.println("Testing Product");
		assertEquals(element.select("ProductObj|Product").text() , "1024_cms");
		System.out.println("Testing Version");
		assertEquals(element.select("ProductObj|Version").text() , "0.7");
		System.out.println("Testing Update");
		assertEquals(element.select("ProductObj|Update").text() , "");
		System.out.println("Testing Edition");
		assertEquals(element.select("ProductObj|Edition").text(), "");
		System.out.println("Testing Language");
		assertEquals(element.select("ProductObj|Language").text() , "");
	}
	
	/**
	 * Test one element no description
	 */
	@Test
	public void test_one_element_no_description()	{

		System.out.println("STIXExtractor.CpeExtractorTest.test_one_element_no_description()");

		String cpeInfo = 
			"<?xml version='1.0' encoding='UTF-8'?> " +
			"    <cpe-list xmlns:meta=\"http://scap.nist.gov/schema/cpe-dictionary-metadata/0.2\" xmlns:scap-core=\"http://scap.nist.gov/schema/scap-core/0.3\" xmlns:config=\"http://scap.nist.gov/schema/configuration/0.1\" xmlns=\"http://cpe.mitre.org/dictionary/2.0\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:ns6=\"http://scap.nist.gov/schema/scap-core/0.1\" xsi:schemaLocation=\"http://scap.nist.gov/schema/configuration/0.1 http://nvd.nist.gov/schema/configuration_0.1.xsd http://scap.nist.gov/schema/scap-core/0.3 http://nvd.nist.gov/schema/scap-core_0.3.xsd http://cpe.mitre.org/dictionary/2.0 http://cpe.mitre.org/files/cpe-dictionary_2.2.xsd http://scap.nist.gov/schema/scap-core/0.1 http://nvd.nist.gov/schema/scap-core_0.1.xsd http://scap.nist.gov/schema/cpe-dictionary-metadata/0.2 http://nvd.nist.gov/schema/cpe-dictionary-metadata_0.2.xsd\"> " +
			"      <generator> " +
			"        <product_name>National Vulnerability Database (NVD)</product_name> " +
			"        <product_version>2.18.0-SNAPSHOT (PRODUCTION)</product_version> " +
			"        <schema_version>2.2</schema_version> " +
			"        <timestamp>2013-03-19T03:50:00.109Z</timestamp> " +
			"      </generator> " +
			"      <cpe-item name=\"cpe:/a:1024cms:1024_cms:0.7\"> " +
			"        <title xml:lddang=\"en-US\">1024cms.org 1024 CMS 0.7</title> " +
			"        <meta:item-metadata modification-date=\"2010-12-14T19:38:32.197Z\" status=\"DRAFT\" nvd-id=\"121218\"/> " +
			"      </cpe-item> " +
			"    </cpe-list> ";

		CpeExtractor cpeExtractor = new CpeExtractor(cpeInfo);
		STIXPackage stixPackage = cpeExtractor.getStixPackage();

		Document doc = Jsoup.parse(stixPackage.toXMLString(), "", Parser.xmlParser());
		Element element = doc.select("cybox|Observable").first();

		System.out.println();
		System.out.println("Testing Id");
		assertEquals(element.select("cybox|Object").attr("id"), "stucco:software-cpe:/a:1024cms:1024_cms:0.7");
		System.out.println("Testing Source");
		assertEquals(element.select("cyboxCommon|Information_Source_Type").text(), "CPE");
		System.out.println("Testing Title");
		assertEquals(element.select("cybox|Title").text(), "Software");
		System.out.println("Testing Description");
		assertEquals(element.select("cybox|Description").text(), "cpe /a 1024cms 1024_cms 0.7");
		System.out.println("Testing Part");
		assertEquals(element.select("cyboxCommon|Property[name=Part]").text(), "/a");
		System.out.println("Testing Vendor");
		assertEquals(element.select("ProductObj|Vendor").text(), "1024cms");
		System.out.println("Testing Product");
		assertEquals(element.select("ProductObj|Product").text() , "1024_cms");
		System.out.println("Testing Version");
		assertEquals(element.select("ProductObj|Version").text() , "0.7");
		System.out.println("Testing Update");
		assertEquals(element.select("ProductObj|Update").text() , "");
		System.out.println("Testing Edition");
		assertEquals(element.select("ProductObj|Edition").text(), "");
		System.out.println("Testing Language");
		assertEquals(element.select("ProductObj|Language").text() , "");
	}
	/**
	 * Test three elements
	 */
	@Test
	public void test_three_elements()	{

		System.out.println("STIXExtractor.CpeExtractorTest.test_three_elements()");

		String cpeInfo = 
			"<?xml version='1.0' encoding='UTF-8'?> " +
			"    <cpe-list xmlns:meta=\"http://scap.nist.gov/schema/cpe-dictionary-metadata/0.2\" xmlns:scap-core=\"http://scap.nist.gov/schema/scap-core/0.3\" xmlns:config=\"http://scap.nist.gov/schema/configuration/0.1\" xmlns=\"http://cpe.mitre.org/dictionary/2.0\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:ns6=\"http://scap.nist.gov/schema/scap-core/0.1\" xsi:schemaLocation=\"http://scap.nist.gov/schema/configuration/0.1 http://nvd.nist.gov/schema/configuration_0.1.xsd http://scap.nist.gov/schema/scap-core/0.3 http://nvd.nist.gov/schema/scap-core_0.3.xsd http://cpe.mitre.org/dictionary/2.0 http://cpe.mitre.org/files/cpe-dictionary_2.2.xsd http://scap.nist.gov/schema/scap-core/0.1 http://nvd.nist.gov/schema/scap-core_0.1.xsd http://scap.nist.gov/schema/cpe-dictionary-metadata/0.2 http://nvd.nist.gov/schema/cpe-dictionary-metadata_0.2.xsd\"> " +
			"      <generator> " +
			"        <product_name>National Vulnerability Database (NVD)</product_name> " +
			"        <product_version>2.18.0-SNAPSHOT (PRODUCTION)</product_version> " +
			"        <schema_version>2.2</schema_version> " +
			"        <timestamp>2013-03-19T03:50:00.109Z</timestamp> " +
			"      </generator> " +
			"      <cpe-item name=\"cpe:/a:microsoft:hotmail\"> " +
			"        <title xml:lang=\"en-US\">Microsoft Hotmail</title> " +
			"        <meta:item-metadata modification-date=\"2007-09-14T17:36:49.090Z\" status=\"DRAFT\" nvd-id=\"7005\"/> " +
			"      </cpe-item> " +
			"      <cpe-item deprecation_date=\"2011-04-20T14:22:38.607Z\" deprecated_by=\"cpe:/o:yamaha:rtx1100:8.03.82\" deprecated=\"true\" name=\"cpe:/o:yahama:rtx1100:8.03.82\"> " +
			"        <title xml:lang=\"en-US\">Yamaha RTX1100 8.03.82</title> " +
			"        <title xml:lang=\"ja-JP\">ヤマハ RTX1100 8.03.82</title> " +
			"        <meta:item-metadata modification-date=\"2011-04-20T14:22:38.607Z\" status=\"DRAFT\" deprecated-by-nvd-id=\"145415\" nvd-id=\"144720\"/> " +
			"      </cpe-item> " +
			"      <cpe-item name=\"cpe:/o:yamaha:srt100:10.00.56\"> " +
			"        <title xml:lang=\"en-US\">Yamaha SRT100 10.00.56</title> " +
			"        <title xml:lang=\"ja-JP\">ヤマハ SRT100 10.00.56</title> " +
			"        <meta:item-metadata modification-date=\"2011-04-20T02:08:53.277Z\" status=\"DRAFT\" nvd-id=\"145456\"/> " +
			"      </cpe-item> " +
			"    </cpe-list> ";

		CpeExtractor cpeExtractor = new CpeExtractor(cpeInfo);
		STIXPackage stixPackage = cpeExtractor.getStixPackage();

		Document doc = Jsoup.parse(stixPackage.toXMLString(), "", Parser.xmlParser());
		
		System.out.println();
		System.out.println("Testing 1st element:");
		Element element = doc.select("cybox|Observable:has(cybox|Object[id=stucco:software-cpe:/a:microsoft:hotmail])").first();

		System.out.println("Testing Id");
		assertEquals(element.select("cybox|Object").attr("id"), "stucco:software-cpe:/a:microsoft:hotmail");
		System.out.println("Testing Source");
		assertEquals(element.select("cyboxCommon|Information_Source_Type").text(), "CPE");
		System.out.println("Testing Title");
		assertEquals(element.select("cybox|Title").text(), "Software");
		System.out.println("Testing Description");
		assertEquals(element.select("cybox|Description").text(), "Microsoft Hotmail");
		System.out.println("Testing Part");
		assertEquals(element.select("cyboxCommon|Property[name=Part]").text(), "/a");
		System.out.println("Testing Vendor");
		assertEquals(element.select("ProductObj|Vendor").text(), "microsoft");
		System.out.println("Testing Product");
		assertEquals(element.select("ProductObj|Product").text() , "hotmail");
		System.out.println("Testing Version");
		assertEquals(element.select("ProductObj|Version").text() , "");
		System.out.println("Testing Update");
		assertEquals(element.select("ProductObj|Update").text() , "");
		System.out.println("Testing Edition");
		assertEquals(element.select("ProductObj|Edition").text(), "");
		System.out.println("Testing Language");
		assertEquals(element.select("ProductObj|Language").text() , "");
		
		System.out.println();
		System.out.println("Testing 2nd element:");
		element = doc.select("cybox|Observable:has(cybox|Object[id=stucco:software-cpe:/o:yahama:rtx1100:8.03.82])").first();

		System.out.println("Testing Id");
		assertEquals(element.select("cybox|Object").attr("id"), "stucco:software-cpe:/o:yahama:rtx1100:8.03.82");
		System.out.println("Testing Source");
		assertEquals(element.select("cyboxCommon|Information_Source_Type").text(), "CPE");
		System.out.println("Testing Title");
		assertEquals(element.select("cybox|Title").text(), "Software");
		System.out.println("Testing Description");
		assertEquals(element.select("cybox|Description").text(), "Yamaha RTX1100 8.03.82");
		System.out.println("Testing Part");
		assertEquals(element.select("cyboxCommon|Property[name=Part]").text(), "/o");
		System.out.println("Testing Vendor");
		assertEquals(element.select("ProductObj|Vendor").text(), "yahama");
		System.out.println("Testing Product");
		assertEquals(element.select("ProductObj|Product").text() , "rtx1100");
		System.out.println("Testing Version");
		assertEquals(element.select("ProductObj|Version").text() , "8.03.82");
		System.out.println("Testing Update");
		assertEquals(element.select("ProductObj|Update").text() , "");
		System.out.println("Testing Edition");
		assertEquals(element.select("ProductObj|Edition").text(), "");
		System.out.println("Testing Language");
		assertEquals(element.select("ProductObj|Language").text() , "");
		
		System.out.println();
		System.out.println("Testing 3rd element:");
		element = doc.select("cybox|Observable:has(cybox|Object[id=stucco:software-cpe:/o:yamaha:srt100:10.00.56])").first();

		System.out.println("Testing Id");
		assertEquals(element.select("cybox|Object").attr("id"), "stucco:software-cpe:/o:yamaha:srt100:10.00.56");
		System.out.println("Testing Source");
		assertEquals(element.select("cyboxCommon|Information_Source_Type").text(), "CPE");
		System.out.println("Testing Title");
		assertEquals(element.select("cybox|Title").text(), "Software");
		System.out.println("Testing Description");
		assertEquals(element.select("cybox|Description").text(), "Yamaha SRT100 10.00.56");
		System.out.println("Testing Part");
		assertEquals(element.select("cyboxCommon|Property[name=Part]").text(), "/o");
		System.out.println("Testing Vendor");
		assertEquals(element.select("ProductObj|Vendor").text(), "yamaha");
		System.out.println("Testing Product");
		assertEquals(element.select("ProductObj|Product").text() , "srt100");
		System.out.println("Testing Version");
		assertEquals(element.select("ProductObj|Version").text() , "10.00.56");
		System.out.println("Testing Update");
		assertEquals(element.select("ProductObj|Update").text() , "");
		System.out.println("Testing Edition");
		assertEquals(element.select("ProductObj|Edition").text(), "");
		System.out.println("Testing Language");
		assertEquals(element.select("ProductObj|Language").text() , "");
	}
}
