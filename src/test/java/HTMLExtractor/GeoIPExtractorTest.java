package STIXExtractor;

import org.jsoup.Jsoup;
import org.jsoup.parser.Parser;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import org.mitre.stix.stix_1.STIXPackage;

import org.junit.Test;

import static org.junit.Assert.*;

import STIXExtractor.GeoIPExtractor;

/**
 * Unit test for GeoIP Extractor.
 */
public class GeoIPExtractorTest	{
	
	/**
	 * Test empty document
	 */
	@Test
	public void test_empty_document()	{

		System.out.println("STIXExtractor.GeoIPExtractorTest.test_empty_document()");

		String geoIpInfo = "";

		GeoIPExtractor geoIPExtractor = new GeoIPExtractor(geoIpInfo);
		STIXPackage stixPackage = geoIPExtractor.getStixPackage();

		System.out.println("Testing that package is null");
		assertTrue(stixPackage == null);
	}

	/**
	 * Test five elements
	 */
	@Test
	public void test_five_elements()	{

		System.out.println("STIXExtractor.GeoIPExtractorTest.test_five_elements()");

		String geoIpInfo =
			"\"StartIP\",\"EndIP\",\"Start IP (int)\",\"End IP (int)\",\"Country code\",\"Country name\"\n" +
			"\"1.0.0.0\",\"1.0.0.255\",\"16777216\",\"16777471\",\"AU\",\"Australia\"\n" + 
			"\"1.0.1.0\",\"1.0.3.255\",\"16777472\",\"16778239\",\"CN\",\"China\"\n" +
			"\"1.0.4.0\",\"1.0.7.255\",\"16778240\",\"16779263\",\"AU\",\"Australia\"\n" + 
			"\"1.0.8.0\",\"1.0.15.255\",\"16779264\",\"16781311\",\"CN\",\"China\"\n" + 
			"\"1.0.16.0\",\"1.0.31.255\",\"16781312\",\"16785407\",\"JP\",\"Japan\"";

		GeoIPExtractor geoIPExtractor = new GeoIPExtractor(geoIpInfo);
		STIXPackage stixPackage = geoIPExtractor.getStixPackage();

		System.out.println("Validating GeoIP stixPackage");
		assertTrue(geoIPExtractor.validate(stixPackage));

		Document doc = Jsoup.parse(stixPackage.toXMLString(), "", Parser.xmlParser());

		System.out.println("Testing 1st element:");
		Element element = doc.select("cybox|Observable:has(cybox|Object[id=stucco:addressRange-16777216_16777471])").first();
		System.out.println("Testing Address");	
		assertEquals(element.select("addressobj|address_value").text(), "1.0.0.0 - 1.0.0.255");
		System.out.println("Testing Description");	
		assertEquals(element.select("cybox|description").text(), "1.0.0.0 through 1.0.0.255");
		System.out.println("Testing Source");	
		assertEquals(element.select("cyboxcommon|information_source_type").text(), "Maxmind");
		System.out.println("Testing Title");	
		assertEquals(element.select("cybox|title").text(), "AddressRange");
		System.out.println("Testing Country Name");	
		assertEquals(element.select("cybox|location > cyboxcommon|name").text(), "Australia");
		System.out.println("Testing Country Code");	
		assertEquals(element.select("cybox|Location").attr("id"), "stucco:countryCode-AU");
		

		System.out.println("Testing 2nd element:");
		element = doc.select("cybox|Observable:has(cybox|Object[id=stucco:addressRange-16777472_16778239])").first();
		System.out.println("Testing Address");	
		assertEquals(element.select("addressobj|address_value").text(), "1.0.1.0 - 1.0.3.255");
		System.out.println("Testing Description");	
		assertEquals(element.select("cybox|description").text(), "1.0.1.0 through 1.0.3.255");
		System.out.println("Testing Source");	
		assertEquals(element.select("cyboxcommon|information_source_type").text(), "Maxmind");
		System.out.println("Testing Title");	
		assertEquals(element.select("cybox|title").text(), "AddressRange");
		System.out.println("Testing Country Name");	
		assertEquals(element.select("cybox|location > cyboxcommon|name").text(), "China");
		System.out.println("Testing Country Code");	
		assertEquals(element.select("cybox|Location").attr("id"), "stucco:countryCode-CN");
		
		
		System.out.println("Testing 3rd element:");
		element = doc.select("cybox|Observable:has(cybox|Object[id=stucco:addressRange-16778240_16779263])").first();
		System.out.println("Testing Address");	
		assertEquals(element.select("addressobj|address_value").text(), "1.0.4.0 - 1.0.7.255");
		System.out.println("Testing Description");	
		assertEquals(element.select("cybox|description").text(), "1.0.4.0 through 1.0.7.255");
		System.out.println("Testing Source");	
		assertEquals(element.select("cyboxcommon|information_source_type").text(), "Maxmind");
		System.out.println("Testing Title");	
		assertEquals(element.select("cybox|title").text(), "AddressRange");
		System.out.println("Testing Country Name");	
		assertEquals(element.select("cybox|location > cyboxcommon|name").text(), "Australia");
		System.out.println("Testing Country Code");	
		assertEquals(element.select("cybox|Location").attr("id"), "stucco:countryCode-AU");
		

		System.out.println("Testing 4th element:");
		element = doc.select("cybox|Observable:has(cybox|Object[id=stucco:addressRange-16779264_16781311])").first();
		System.out.println("Testing Address");	
		assertEquals(element.select("addressobj|address_value").text(), "1.0.8.0 - 1.0.15.255");
		System.out.println("Testing  Description");	
		assertEquals(element.select("cybox|description").text(), "1.0.8.0 through 1.0.15.255");
		System.out.println("Testing Source");	
		assertEquals(element.select("cyboxcommon|information_source_type").text(), "Maxmind");
		System.out.println("Testing Title");	
		assertEquals(element.select("cybox|title").text(), "AddressRange");
		System.out.println("Testing Country Name");	
		assertEquals(element.select("cybox|location > cyboxcommon|name").text(), "China");
		System.out.println("Testing Country Code");	
		assertEquals(element.select("cybox|Location").attr("id"), "stucco:countryCode-CN");
		
	
		System.out.println("Testing 5th element:");
		element = doc.select("cybox|Observable:has(cybox|Object[id=stucco:addressRange-16781312_16785407])").first();
		System.out.println("Testing Address");	
		assertEquals(element.select("addressobj|address_value").text(), "1.0.16.0 - 1.0.31.255");
		System.out.println("Testing Description");	
		assertEquals(element.select("cybox|description").text(), "1.0.16.0 through 1.0.31.255");
		System.out.println("Testing Source");	
		assertEquals(element.select("cyboxcommon|information_source_type").text(), "Maxmind");
		System.out.println("Testing Title");	
		assertEquals(element.select("cybox|title").text(), "AddressRange");
		System.out.println("Testing Country Name");	
		assertEquals(element.select("cybox|location > cyboxcommon|name").text(), "Japan");
		System.out.println("Testing Country Code");	
		assertEquals(element.select("cybox|Location").attr("id"), "stucco:countryCode-JP");
	}
	
	/**
	 * Test three elements with no header
	 */
	@Test
	public void test_three_elements_no_header()	{

		System.out.println("STIXExtractor.GeoIPExtractorTest.test_three_elements_no_header()");

		String geoIpInfo =
			"\"223.255.252.0\",\"223.255.253.255\",\"3758095360\",\"3758095871\",\"CN\",\"China\"\n" +
			"\"223.255.254.0\",\"223.255.254.255\",\"3758095872\",\"3758096127\",\"SG\",\"Singapore\"\n" +
			"\"223.255.255.0\",\"223.255.255.255\",\"3758096128\",\"3758096383\",\"AU\",\"Australia\"";

		GeoIPExtractor geoIPExtractor = new GeoIPExtractor(geoIpInfo);
		STIXPackage stixPackage = geoIPExtractor.getStixPackage();

		System.out.println("Validating GeoIP stixPackage");
		assertTrue(geoIPExtractor.validate(stixPackage));

		Document doc = Jsoup.parse(stixPackage.toXMLString(), "", Parser.xmlParser());

		System.out.println("Testing 1st element:");
		Element element = doc.select("cybox|Observable:has(cybox|Object[id=stucco:addressRange-3758095360_3758095871])").first();
		System.out.println("Testing Address");	
		assertEquals(element.select("addressobj|address_value").text(), "223.255.252.0 - 223.255.253.255");
		System.out.println("Testing Description");	
		assertEquals(element.select("cybox|description").text(), "223.255.252.0 through 223.255.253.255");
		System.out.println("Testing Source");	
		assertEquals(element.select("cyboxcommon|information_source_type").text(), "Maxmind");
		System.out.println("Testing Title");	
		assertEquals(element.select("cybox|title").text(), "AddressRange");
		System.out.println("Testing Country Name");	
		assertEquals(element.select("cybox|location > cyboxcommon|name").text(), "China");
		System.out.println("Testing Country Code");	
		assertEquals(element.select("cybox|Location").attr("id"), "stucco:countryCode-CN");
		

		System.out.println("Testing 2st element:");
		element = doc.select("cybox|Observable:has(cybox|Object[id=stucco:addressRange-3758095872_3758096127])").first();
		System.out.println("Testing Address");	
		assertEquals(element.select("addressobj|address_value").text(), "223.255.254.0 - 223.255.254.255");
		System.out.println("Testing Description");	
		assertEquals(element.select("cybox|description").text(), "223.255.254.0 through 223.255.254.255");
		System.out.println("Testing Source");	
		assertEquals(element.select("cyboxcommon|information_source_type").text(), "Maxmind");
		System.out.println("Testing Title");	
		assertEquals(element.select("cybox|title").text(), "AddressRange");
		System.out.println("Testing Country Name");	
		assertEquals(element.select("cybox|location > cyboxcommon|name").text(), "Singapore");
		System.out.println("Testing Country Code");	
		assertEquals(element.select("cybox|Location").attr("id"), "stucco:countryCode-SG");
		

		System.out.println("Testing 3st element:");
		element = doc.select("cybox|Observable:has(cybox|Object[id=stucco:addressRange-3758096128_3758096383])").first();
		System.out.println("Testing Address");	
		assertEquals(element.select("addressobj|address_value").text(), "223.255.255.0 - 223.255.255.255");
		System.out.println("Testing Description");	
		assertEquals(element.select("cybox|description").text(), "223.255.255.0 through 223.255.255.255");
		System.out.println("Testing Source");	
		assertEquals(element.select("cyboxcommon|information_source_type").text(), "Maxmind");
		System.out.println("Testing Title");	
		assertEquals(element.select("cybox|title").text(), "AddressRange");
		System.out.println("Testing Country Name");	
		assertEquals(element.select("cybox|location > cyboxcommon|name").text(), "Australia");
		System.out.println("Testing Country Code");	
		assertEquals(element.select("cybox|Location").attr("id"), "stucco:countryCode-AU");
	}
}
