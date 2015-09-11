package STIXExtractor;

import java.util.List;
import java.util.ArrayList;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;
import org.jsoup.parser.Parser;

import org.mitre.stix.stix_1.STIXPackage;

import org.junit.Test;

import static org.junit.Assert.*;

import STIXExtractor.CaidaExtractor;

/**
 * Unit test for Caida Extractor.
 */
public class CaidaExtractorTest extends STIXExtractor {
	
	/**
	 * Test empty doc
	 */
	@Test
	public void test_empty_doc_no_headers() {

		System.out.println();
		System.out.println("STIXExtractor.CaidaExtractorTest.test_empty_doc_no_headers()");

		String as2orgInfo = "";

		String pfx2asInfo = "";

		CaidaExtractor caidaExtractor = new CaidaExtractor(as2orgInfo, pfx2asInfo);
		STIXPackage stixPackage = caidaExtractor.getStixPackage();
	
		assertTrue(stixPackage == null);
	}

	/**
	 * Test empty doc
	 */
	@Test
	public void test_empty_doc() {

		System.out.println();
		System.out.println("STIXExtractor.CaidaExtractorTest.test_empty_doc()");

		String as2orgInfo = 
			"# format:org_id|changed|org_name|country|source\n" +
			"# format:aut|changed|aut_name|org_id|source\n";

		String pfx2asInfo = "";

		CaidaExtractor caidaExtractor = new CaidaExtractor(as2orgInfo, pfx2asInfo);
		STIXPackage stixPackage = caidaExtractor.getStixPackage();
	
		assertTrue(stixPackage == null);
	}

	/**
	 * Test doc with just organizaiton info
	 */
	@Test
	public void test_empty_doc_with_org_info() {

		System.out.println();
		System.out.println("STIXExtractor.CaidaExtractorTest.test_empty_doc_with_org_info()");

		String as2orgInfo = 
			"# format:org_id|changed|org_name|country|source\n" + 
			"01CO-ARIN|20150430|O1.com|US|ARIN\n" +
			"# format:aut|changed|aut_name|org_id|source\n";

		String pfx2asInfo = "";

		CaidaExtractor caidaExtractor = new CaidaExtractor(as2orgInfo, pfx2asInfo);
		STIXPackage stixPackage = caidaExtractor.getStixPackage();
	
		assertTrue(stixPackage == null);
	}
	
	/**
	 * Test one element with just asn info
	 */
	@Test
	public void test_one_element_with_asn() {

		System.out.println();
		System.out.println("STIXExtractor.CaidaExtractorTest.test_one_element_with_asn()");

		String as2orgInfo = 
			"# format:org_id|changed|org_name|country|source\n" + 
			"# format:aut|changed|aut_name|org_id|source\n" +
			"19864|20120320|O1COMM|01CO-ARIN|ARIN";

		String pfx2asInfo =
			"";

		CaidaExtractor caidaExtractor = new CaidaExtractor(as2orgInfo, pfx2asInfo);
		STIXPackage stixPackage = caidaExtractor.getStixPackage();
	
		assertTrue(stixPackage == null);
	}

	/**
	 * Test one element with just asn  and prefix info and no org
	 */
	@Test
	public void test_one_element_no_org() {

		System.out.println();
		System.out.println("STIXExtractor.CaidaExtractorTest.test_one_element_no_org()");

		String as2orgInfo = 
			"# format:org_id|changed|org_name|country|source\n" + 
			"# format:aut|changed|aut_name|org_id|source\n" +
			"19864|20120320|O1COMM|01CO-ARIN|ARIN";

		String pfx2asInfo =
			"69.19.190.12	24	19864";


		CaidaExtractor caidaExtractor = new CaidaExtractor(as2orgInfo, pfx2asInfo);
		STIXPackage stixPackage = caidaExtractor.getStixPackage();

		System.out.println(stixPackage.toXMLString(true));

		System.out.println("Validating Caida stixPackage");
		assertTrue(caidaExtractor.validate(stixPackage));

		Document doc = Jsoup.parse(stixPackage.toXMLString(), "", Parser.xmlParser());
		Element asn = doc.select("cybox|Observable:has(cybox|Title:contains(AS))").first();

		System.out.println();
		System.out.println("Testing AS");
		System.out.println("Testing Title");
		assertEquals(asn.select("cybox|Title").text(), "AS");
		System.out.println("Testing Source");
		assertEquals(asn.select("cybox|Observable_Source > cyboxCommon|Information_Source_Type").text(), "Caida");
		System.out.println("Testing ASN value");
		assertEquals(asn.select("ASObj|Number").text(), "19864");
		System.out.println("Testing AS name");
		assertEquals(asn.select("ASObj|Name").text(), "O1COMM");
		System.out.println("Testing RIR");
		assertEquals(asn.select("ASObj|Regional_Internet_Registry").text(), "ARIN");
		System.out.println("Testing Description");
		assertEquals(asn.select("cybox|Object > cybox|Description").text(), "AS O1COMM has ASN 19864");
		System.out.println("Testing ASN -> AddressRange");
		String idref = asn.select("cybox|Related_Object").attr("idref");
		Element addressRange = doc.select("[id = " + idref + "]").first();
		
		System.out.println();
		System.out.println("Testing AddressRange");
		System.out.println("Testing Title");	
		assertEquals(addressRange.select("cybox|title").text(), "AddressRange");
		System.out.println("Testing Source");	
		assertEquals(addressRange.select("cyboxcommon|information_source_type").text(), "Caida");
		System.out.println("Testing AddressRange value");	
		assertEquals(addressRange.select("addressobj|address_value").text(), "69.19.190.0 - 69.19.190.255");
		System.out.println("Testing Description");	
		assertEquals(addressRange.select("cybox|description").text(), "69.19.190.0 through 69.19.190.255");
	}
	
	/**
	 * Test one element
	 */
	@Test
	public void test_one_element() {

		System.out.println();
		System.out.println("STIXExtractor.CaidaExtractorTest.test_one_element()");

		String as2orgInfo = 
			"# format:org_id|changed|org_name|country|source\n" + 
			"01CO-ARIN|20150430|O1.com|US|ARIN\n" +
			"# format:aut|changed|aut_name|org_id|source\n" +
			"19864|20120320|O1COMM|01CO-ARIN|ARIN";

		String pfx2asInfo =
			"69.19.190.0	24	19864";

		CaidaExtractor caidaExtractor = new CaidaExtractor(as2orgInfo, pfx2asInfo);
		STIXPackage stixPackage = caidaExtractor.getStixPackage();
		
	
		System.out.println("Validating Caida stixPackage");
		assertTrue(caidaExtractor.validate(stixPackage));

		Document doc = Jsoup.parse(stixPackage.toXMLString(), "", Parser.xmlParser());

		System.out.println();
		System.out.println("Testing Organization");
		Element org = doc.select("cybox|Observable:has(cybox|Title:contains(Organization))").first();
		System.out.println("Testing Title");
		assertEquals(org.select("cybox|title").text(), "Organization");
		System.out.println("Testing Source");
		assertEquals(org.select("cybox|Observable_Source > cyboxCommon|Information_Source_Type").text(), "Caida");
		System.out.println("Testing Name");
		assertEquals(org.select("WhoisObj|Organization").text(), "O1.com");
		System.out.println("Testing OrgId");
		assertEquals(org.select("WhoisObj|Registrant_ID").text(), "01CO-ARIN");
		System.out.println("Testing Address");
		assertEquals(org.select("WhoisObj|Address").text(), "US");
		System.out.println("Testing Organization > ASN");
		String asnId = org.select("WhoisObj|IP_Address").attr("object_reference");
		Element asn = doc.select("[id = " + asnId + "]").first();

		System.out.println();
		System.out.println("Testing AS");
		System.out.println("Testing Title");
		assertEquals(asn.select("cybox|Title").text(), "AS");
		System.out.println("Testing Source");
		assertEquals(asn.select("cybox|Observable_Source > cyboxCommon|Information_Source_Type").text(), "Caida");
		System.out.println("Testing ASN value");
		assertEquals(asn.select("ASObj|Number").text(), "19864");
		System.out.println("Testing AS name");
		assertEquals(asn.select("ASObj|Name").text(), "O1COMM");
		System.out.println("Testing RIR");
		assertEquals(asn.select("ASObj|Regional_Internet_Registry").text(), "ARIN");
		System.out.println("Testing Description");
		assertEquals(asn.select("cybox|Object > cybox|Description").text(), "AS O1COMM has ASN 19864");
		System.out.println("Testing ASN -> AddressRange");
		String idref = asn.select("cybox|Related_Object").attr("idref");
		Element addressRange = doc.select("[id = " + idref + "]").first();
		
		System.out.println();
		System.out.println("Testing AddressRange");
		System.out.println("Testing Title");	
		assertEquals(addressRange.select("cybox|title").text(), "AddressRange");
		System.out.println("Testing Source");	
		assertEquals(addressRange.select("cyboxcommon|information_source_type").text(), "Caida");
		System.out.println("Testing AddressRange value");	
		assertEquals(addressRange.select("addressobj|address_value").text(), "69.19.190.0 - 69.19.190.255");
		System.out.println("Testing Description");	
		assertEquals(addressRange.select("cybox|description").text(), "69.19.190.0 through 69.19.190.255");
	}
	
	/**
	 * Test one element with just org and asn
	 */
	@Test
	public void test_one_element_org_asn() {

		System.out.println();
		System.out.println("STIXExtractor.CaidaExtractorTest.test_one_element_org_asn()");

		String as2orgInfo = 
			"# format:org_id|changed|org_name|country|source\n" + 
			"111S-ARIN|20141114|One Eleven Internet Services|US|ARIN\n" +
			"# format:aut|changed|aut_name|org_id|source\n" +
			"12285|20120329|ONE-ELEVEN|111S-ARIN|ARIN";

		String pfx2asInfo =
			"";

		CaidaExtractor caidaExtractor = new CaidaExtractor(as2orgInfo, pfx2asInfo);
		STIXPackage stixPackage = caidaExtractor.getStixPackage();
	
		System.out.println("Validating Caida stixPackage");
		assertTrue(caidaExtractor.validate(stixPackage));
		
		Document doc = Jsoup.parse(stixPackage.toXMLString(), "", Parser.xmlParser());

		System.out.println();
		System.out.println("Testing Organization");
		Element org = doc.select("cybox|Observable:has(cybox|Title:contains(Organization))").first();
		System.out.println("Testing Title");
		assertEquals(org.select("cybox|title").text(), "Organization");
		System.out.println("Testing Source");
		assertEquals(org.select("cybox|Observable_Source > cyboxCommon|Information_Source_Type").text(), "Caida");
		System.out.println("Testing Name");
		assertEquals(org.select("WhoisObj|Organization").text(), "One Eleven Internet Services");
		System.out.println("Testing OrgId");
		assertEquals(org.select("WhoisObj|Registrant_ID").text(), "111S-ARIN");
		System.out.println("Testing Address");
		assertEquals(org.select("WhoisObj|Address").text(), "US");
		System.out.println("Testing Organization -> ASN");
		String asnId = org.select("WhoisObj|IP_Address").attr("object_reference");
		Element asn = doc.select("[id = " + asnId + "]").first();

		System.out.println();
		System.out.println("Testing AS");
		System.out.println("Testing Title");
		assertEquals(asn.select("cybox|Title").text(), "AS");
		System.out.println("Testing Source");
		assertEquals(asn.select("cybox|Observable_Source > cyboxCommon|Information_Source_Type").text(), "Caida");
		System.out.println("Testing ASN value");
		assertEquals(asn.select("ASObj|Number").text(), "12285");
		System.out.println("Testing AS name");
		assertEquals(asn.select("ASObj|Name").text(), "ONE-ELEVEN");
		System.out.println("Testing RIR");
		assertEquals(asn.select("ASObj|Regional_Internet_Registry").text(), "ARIN");
		System.out.println("Testing Description");
		assertEquals(asn.select("cybox|Object > cybox|Description").text(), "AS ONE-ELEVEN has ASN 12285");
	}
	
	/**
	 * Test two elements
	 */
	@Test
	public void test_two_elements() {

		System.out.println();
		System.out.println("STIXExtractor.CaidaExtractorTest.test_two_elements()");

		String as2orgInfo = 
			"# format:org_id|changed|org_name|country|source\n" + 
			"111S-ARIN|20141114|One Eleven Internet Services|US|RIPE\n" +
			"18VO-ARIN|20121010|1 800 Video On, Inc.|US|ARIN\n" + 
			"# format:aut|changed|aut_name|org_id|source\n" +
			"18548|20020114|18VO|18VO-ARIN|ARIN\n" +
			"12285|20120329|ONE-ELEVEN|111S-ARIN|ARIN";

		String pfx2asInfo =
			"216.98.179.0	24	18548\n" +
			"216.98.188.0	24	18548\n" +
			"69.19.190.0	24	19864\n";

		CaidaExtractor caidaExtractor = new CaidaExtractor(as2orgInfo, pfx2asInfo);
		STIXPackage stixPackage = caidaExtractor.getStixPackage();

		System.out.println("Validating Caida stixPackage");
		assertTrue(caidaExtractor.validate(stixPackage));
		
		Document doc = Jsoup.parse(stixPackage.toXMLString(), "", Parser.xmlParser());

		System.out.println();
		System.out.println("Testing Organization");
		Element org = doc.select("cybox|Observable:has(WhoisObj|Organization:contains(One Eleven Internet Services))").first();
		System.out.println("Testing Title");
		assertEquals(org.select("cybox|title").text(), "Organization");
		System.out.println("Testing Source");
		assertEquals(org.select("cybox|Observable_Source > cyboxCommon|Information_Source_Type").text(), "Caida");
		System.out.println("Testing Name");
		assertEquals(org.select("WhoisObj|Organization").text(), "One Eleven Internet Services");
		System.out.println("Testing OrgId");
		assertEquals(org.select("WhoisObj|Registrant_ID").text(), "111S-ARIN");
		System.out.println("Testing Address");
		assertEquals(org.select("WhoisObj|Address").text(), "US");
		System.out.println("Testing Organization -> ASN");
		String asnId = org.select("WhoisObj|IP_Address").attr("object_reference");
		Element asn = doc.select("[id = " + asnId + "]").first();

		System.out.println();
		System.out.println("Testing AS");
		System.out.println("Testing Title");
		assertEquals(asn.select("cybox|Title").text(), "AS");
		System.out.println("Testing Source");
		assertEquals(asn.select("cybox|Observable_Source > cyboxCommon|Information_Source_Type").text(), "Caida");
		System.out.println("Testing ASN value");
		assertEquals(asn.select("ASObj|Number").text(), "12285");
		System.out.println("Testing AS name");
		assertEquals(asn.select("ASObj|Name").text(), "ONE-ELEVEN");
		System.out.println("Testing RIR");
		assertEquals(asn.select("ASObj|Regional_Internet_Registry").text(), "ARIN");
		System.out.println("Testing Description");
		assertEquals(asn.select("cybox|Object > cybox|Description").text(), "AS ONE-ELEVEN has ASN 12285");

		System.out.println();
		System.out.println("Testing Organization");
		org = doc.select("cybox|Observable:has(WhoisObj|Organization:contains(1 800 Video On, Inc.))").first();
		System.out.println("Testing Title");
		assertEquals(org.select("cybox|title").text(), "Organization");
		System.out.println("Testing Source");
		assertEquals(org.select("cybox|Observable_Source > cyboxCommon|Information_Source_Type").text(), "Caida");
		System.out.println("Testing Name");
		assertEquals(org.select("WhoisObj|Organization").text(), "1 800 Video On, Inc.");
		System.out.println("Testing OrgId");
		assertEquals(org.select("WhoisObj|Registrant_ID").text(), "18VO-ARIN");
		System.out.println("Testing Address");
		assertEquals(org.select("WhoisObj|Address").text(), "US");
		System.out.println("Testing Organization -> ASN");
		asnId = org.select("WhoisObj|IP_Address").attr("object_reference");
		asn = doc.select("[id = " + asnId + "]").first();

		System.out.println();
		System.out.println("Testing AS");
		System.out.println("Testing Title");
		assertEquals(asn.select("cybox|Title").text(), "AS");
		System.out.println("Testing Source");
		System.out.println("Testing ASN value");
		assertEquals(asn.select("ASObj|Number").text(), "18548");
		System.out.println("Testing AS name");
		assertEquals(asn.select("ASObj|Name").text(), "18VO");
		assertEquals(asn.select("cybox|Observable_Source > cyboxCommon|Information_Source_Type").text(), "Caida");
		System.out.println("Testing RIR");
		assertEquals(asn.select("ASObj|Regional_Internet_Registry").text(), "ARIN");
		System.out.println("Testing Description");
		assertEquals(asn.select("cybox|Object > cybox|Description").text(), "AS 18VO has ASN 18548");


		System.out.println("Testing ASN -> AddressRange");
		Elements idrefs = asn.select("cybox|Related_Object");
		List<String> address = new ArrayList();
		for (Element id : idrefs) {
			String idref = id.attr("idref");
			Element addr = doc.select("[id = " + idref + "]").first();
			address.add(addr.select("AddressObj|Address_Value").text());
		}
		assertTrue(address.contains("216.98.179.0 - 216.98.179.255"));
		assertTrue(address.contains("216.98.188.0 - 216.98.188.255"));

		System.out.println();
		System.out.println("Testing AddressRange");
		Element addressRange = doc.select("cybox|Observable:has(AddressObj|Address_Value:contains(216.98.179.0 - 216.98.179.255))").first();
		System.out.println("Testing Title");	
		assertEquals(addressRange.select("cybox|title").text(), "AddressRange");
		System.out.println("Testing Source");	
		assertEquals(addressRange.select("cyboxcommon|information_source_type").text(), "Caida");
		System.out.println("Testing AddressRange value");	
		assertEquals(addressRange.select("addressobj|address_value").text(), "216.98.179.0 - 216.98.179.255");
		System.out.println("Testing Description");	
		assertEquals(addressRange.select("cybox|description").text(), "216.98.179.0 through 216.98.179.255");

		System.out.println();
		System.out.println("Testing AddressRange");
		addressRange = doc.select("cybox|Observable:has(AddressObj|Address_Value:contains(216.98.188.0 - 216.98.188.255))").first();
		System.out.println("Testing Title");	
		assertEquals(addressRange.select("cybox|title").text(), "AddressRange");
		System.out.println("Testing Source");	
		assertEquals(addressRange.select("cyboxcommon|information_source_type").text(), "Caida");
		System.out.println("Testing AddressRange value");	
		assertEquals(addressRange.select("addressobj|address_value").text(), "216.98.188.0 - 216.98.188.255");
		System.out.println("Testing Description");	
		assertEquals(addressRange.select("cybox|description").text(), "216.98.188.0 through 216.98.188.255");
		
	}
}
