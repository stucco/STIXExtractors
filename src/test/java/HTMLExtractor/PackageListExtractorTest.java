package STIXExtractor;

import org.jsoup.Jsoup;
import org.jsoup.parser.Parser;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import org.mitre.stix.stix_1.STIXPackage;

import org.junit.Test;

import static org.junit.Assert.*;

import STIXExtractor.PackageListExtractor;

/**
 * Unit test for PackageList Extractor.
 */
public class PackageListExtractorTest	{
	
	/**
	 * Test empty document
	 */
	@Test
	public void test_empty_document()	{

		System.out.println("STIXExtractor.PackageListExtractorTest.test_empty_document()");

		String packageInfo = "";

		PackageListExtractor packageListExtractor = new PackageListExtractor(packageInfo);
		STIXPackage stixPackage = packageListExtractor.getStixPackage();

		System.out.println("Testing that package is null");
		assertTrue(stixPackage == null);
	}

	/**
	 * Test one element with header
	 */
	@Test
	public void test_one_element_with_header()	{

		System.out.println("STIXExtractor.PackageListExtractorTest.test_one_element_with_header()");

		String packageInfo = "hostname,package,version \n" +
					"stucco1,ftp,0.17-25";

		PackageListExtractor packageListExtractor = new PackageListExtractor(packageInfo);
		STIXPackage stixPackage = packageListExtractor.getStixPackage();

		System.out.println("Validating PackageList stixPackage");
		assertTrue(packageListExtractor.validate(stixPackage));

		Document doc = Jsoup.parse(stixPackage.toXMLString(), "", Parser.xmlParser());

		System.out.println("Testing Software:");	
		Element element = doc.select("cybox|Observable:has(ProductObj|Product)").first();

		System.out.println("Testing Id");	
		assertEquals(element.select("cybox|Object").attr("id"), "stucco:software-ftp_0.17-25");
		System.out.println("Testing Description");	
		assertEquals(element.select("cybox|description").text(), "ftp version 0.17-25");
		System.out.println("Testing Source");	
		assertEquals(element.select("cyboxcommon|information_source_type").text(), "PackageList");
		System.out.println("Testing Title");	
		assertEquals(element.select("cybox|title").text(), "Software");
		System.out.println("Testing Product");	
		assertEquals(element.select("ProductObj|Product").text(), "ftp");
		System.out.println("Testing Version");	
		assertEquals(element.select("ProductObj|Version").text(), "0.17-25");


		System.out.println("Testing Hostname:");	
		element = doc.select("cybox|Observable:has(HostnameObj|Hostname_Value)").first();

		System.out.println("Testing Id");	
		assertEquals(element.select("cybox|Object").attr("id"), "stucco:hostname-stucco1");
		System.out.println("Testing Description");	
		assertEquals(element.select("cybox|description").text(), "stucco1");
		System.out.println("Testing Source");	
		assertEquals(element.select("cyboxcommon|information_source_type").text(), "PackageList");
		System.out.println("Testing Title");	
		assertEquals(element.select("cybox|title").text(), "Hostname");
		System.out.println("Testing Hostname");	
		assertEquals(element.select("HostnameObj|Hostname_Value").text(), "stucco1");
		System.out.println("Testing Hostname -> Software IdRef");	
		assertEquals(element.select("cybox|Related_Object").attr("idref"), doc.select("cybox|Observable:has(ProductObj|Product)").attr("id"));
		
	}
	
	/**
	 * Test two elements with no header
	 */
	@Test
	public void test_two_elements_with_no_header()	{

		System.out.println("STIXExtractor.PackageListExtractorTest.test_two_elements_with_no_header()");

		String packageInfo = 
					"stucco1,ftp,0.17-25\n" +
					"stucco2,Notes,1.2";

		PackageListExtractor packageListExtractor = new PackageListExtractor(packageInfo);
		STIXPackage stixPackage = packageListExtractor.getStixPackage();

		System.out.println("Validating PackageList stixPackage");
		assertTrue(packageListExtractor.validate(stixPackage));

		Document doc = Jsoup.parse(stixPackage.toXMLString(), "", Parser.xmlParser());

		System.out.println("Testing 1st element:");

		System.out.println("Testing Software:");	
		Element element = doc.select("cybox|Observable:has(ProductObj|Product:contains(ftp)").first();

		System.out.println("Testing Id");	
		assertEquals(element.select("cybox|Object").attr("id"), "stucco:software-ftp_0.17-25");
		System.out.println("Testing Description");	
		assertEquals(element.select("cybox|description").text(), "ftp version 0.17-25");
		System.out.println("Testing Source");	
		assertEquals(element.select("cyboxcommon|information_source_type").text(), "PackageList");
		System.out.println("Testing Title");	
		assertEquals(element.select("cybox|title").text(), "Software");
		System.out.println("Testing Product");	
		assertEquals(element.select("ProductObj|Product").text(), "ftp");
		System.out.println("Testing Version");	
		assertEquals(element.select("ProductObj|Version").text(), "0.17-25");


		System.out.println("Testing Hostname:");	
		element = doc.select("cybox|Observable:has(HostnameObj|Hostname_Value:contains(stucco1))").first();

		System.out.println("Testing Id");	
		assertEquals(element.select("cybox|Object").attr("id"), "stucco:hostname-stucco1");
		System.out.println("Testing Description");	
		assertEquals(element.select("cybox|description").text(), "stucco1");
		System.out.println("Testing Source");	
		assertEquals(element.select("cyboxcommon|information_source_type").text(), "PackageList");
		System.out.println("Testing Title");	
		assertEquals(element.select("cybox|title").text(), "Hostname");
		System.out.println("Testing Hostname");	
		System.out.println("Testing Hostname -> Software IdRef");	
		assertEquals(element.select("cybox|Related_Object").attr("idref"), doc.select("cybox|Observable:has(ProductObj|Product:contains(ftp))").attr("id"));
		
		System.out.println("Testing 2nd element:");

		System.out.println("Testing Software:");	
		element = doc.select("cybox|Observable:has(ProductObj|Product:contains(Notes)").first();

		System.out.println("Testing Id");	
		assertEquals(element.select("cybox|Object").attr("id"), "stucco:software-Notes_1.2");
		System.out.println("Testing Description");	
		assertEquals(element.select("cybox|description").text(), "Notes version 1.2");
		System.out.println("Testing Source");	
		assertEquals(element.select("cyboxcommon|information_source_type").text(), "PackageList");
		System.out.println("Testing Title");	
		assertEquals(element.select("cybox|title").text(), "Software");
		System.out.println("Testing Product");	
		assertEquals(element.select("ProductObj|Product").text(), "Notes");
		System.out.println("Testing Version");	
		assertEquals(element.select("ProductObj|Version").text(), "1.2");


		System.out.println("Testing Hostname:");	
		element = doc.select("cybox|Observable:has(HostnameObj|Hostname_Value:contains(stucco2))").first();

		System.out.println("Testing Id");	
		assertEquals(element.select("cybox|Object").attr("id"), "stucco:hostname-stucco2");
		System.out.println("Testing Description");	
		assertEquals(element.select("cybox|description").text(), "stucco2");
		System.out.println("Testing Source");	
		assertEquals(element.select("cyboxcommon|information_source_type").text(), "PackageList");
		System.out.println("Testing Title");	
		assertEquals(element.select("cybox|title").text(), "Hostname");
		System.out.println("Testing Hostname");	
		System.out.println("Testing Hostname -> Software IdRef");	
		assertEquals(element.select("cybox|Related_Object").attr("idref"), doc.select("cybox|Observable:has(ProductObj|Product:contains(Notes))").attr("id"));
	}
}
