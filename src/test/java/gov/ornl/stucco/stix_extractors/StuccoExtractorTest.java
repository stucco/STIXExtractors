package gov.ornl.stucco.stix_extractors;

import java.nio.charset.Charset;

import org.jsoup.Jsoup;
import org.jsoup.parser.Parser;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import org.json.JSONObject;  
import org.junit.Test;

import org.mitre.stix.stix_1.STIXPackage;
						
import static org.junit.Assert.*;

/**
 * Unit test for stucco extracted data from unstructured sources to STIX 
 */			
public class StuccoExtractorTest {
	
	/**
	 * Tests empty json
	 */
	@Test
	public void test_empty_doc()	{
		System.out.println("STIXExtractor.NvdToStixExtractorTest.test_empty_doc()");
			
		JSONObject graph = new JSONObject();
		
		StuccoExtractor stuccoExt = new StuccoExtractor(graph);
		STIXPackage stixPackage = stuccoExt.getStixPackage();
		
		System.out.println("Testing that StixPackage is null");
		assertTrue(stixPackage == null);
	}
	
	/**
	 * Tests json with 5 vertices and 4 edges
	 */
	@Test
	public void test_graph()	{
		System.out.println("STIXExtractor.NvdToStixExtractorTest.test_graph()");

		String stuccoInfo =
			"{" +
			"	\"edges\": [ " +
			"		{ " +  
			"			\"outVertID\": \"1236\", " +
			"			\"inVertID\": \"1235\", " +
			"			\"relation\": \"ExploitTargetRelatedObservable\" " +
			"		}, " +
			"		{ " +
			"			\"outVertID\": \"1239\", " +
			"			\"inVertID\": \"1237\", " +
			"			\"relation\": \"ExploitTargetRelatedObservable\" " +
			"		}, " +
			"		{ " +
			"			\"outVertID\": \"1236\", " +
			"			\"inVertID\": \"1237\", " +
			"			\"relation\": \"ExploitTargetRelatedObservable\", " +
			"		}, " +
			"		{ " +
			"			\"outVertID\": \"1237\", " +
			"			\"inVertID\": \"1235\", " +
			"			\"relation\": \"Sub-Observable\", " +
			"		} " +
			"	], " +
			"	\"vertices\": { " +
			"		\"1235\": { " +
			"			\"name\": \"file.php\", " +
			"			\"source\": \"CNN\", " +
			"			\"vertexType\": \"file\" " +
			"		}, " +
			"		\"1236\": { " +
			"			\"cve\": \"CVE-2014-1234\", " +
			"			\"name\": \"1236\", " +
			"			\"source\": \"CNN\", " +
			"			\"vertexType\": \"vulnerability\" " +
			"		}, " +
			"		\"1237\": { " +
			"			\"name\": \"1237\", " +
			"			\"product\": \"Windows XP\", " +
			"			\"source\": \"CNN\", " +
			"			\"vendor\": \"Microsoft\", " +
			"			\"vertexType\": \"software\" " +
			"		}, " +
			"		\"1239\": { " +
			"			\"description\": \"cross-site scripting\", " +
			"			\"name\": \"1239\", " +
			"			\"source\": \"CNN\", " +
			"			\"vertexType\": \"vulnerability\" " +
			"		}, " +
			"		\"1244\": { " +
			"			\"ms\": \"MS15-035\", " +
			"			\"name\": \"1244\", " +
			"			\"source\": \"CNN\", " +
			"			\"vertexType\": \"vulnerability\" " +
			"		}, " +
			"		\"1245\": { " +
			"			\"name\": \"?CDrawPoly::Serialize\", " +
			"			\"source\": \"CNN\", " +
			"			\"vertexType\": \"function\" " +
			"		} " +
			"	} " +
			"}";

		JSONObject graph = new JSONObject(stuccoInfo);
		StuccoExtractor stuccoExt = new StuccoExtractor(graph);
		STIXPackage stixPackage = stuccoExt.getStixPackage();
		Document doc = Jsoup.parse(stixPackage.toXMLString(), "", Parser.xmlParser());

		System.out.println("Testing File ... ");
		Elements file = doc.select("cybox|Observable:has(cybox|Object > cybox|Properties > FileObj|File_Name:contains(file.php))");
		String fileName = file.select("cybox|Observable > cybox|Object > cybox|Properties > FileObj|File_Name").text();
		assertEquals(fileName, "file.php");
		String source = file.select("cybox|Observable > cybox|Observable_Source > cyboxCommon|Information_Source_Type").text();
		assertEquals(source, "CNN");

		System.out.println("Test Software ... ");
		Elements software = doc.select("cybox|Observable:has(cybox|Object > cybox|Properties > ProductObj|Product:contains(Windows XP))");
		String softwareProduct = software.select("cybox|Observable > cybox|Object > cybox|Properties > ProductObj|Product").text();
		assertEquals(softwareProduct, "Windows XP");
		String softwareVendor = software.select("cybox|Observable > cybox|Object > cybox|Properties > ProductObj|Vendor").text();
		assertEquals(softwareVendor, "Microsoft");
		source = file.select("cybox|Observable > cybox|Observable_Source > cyboxCommon|Information_Source_Type").text();
		assertEquals(source, "CNN");

		System.out.println("Testing Function ...");
		Elements function = doc.select("cybox|Observable:has(cybox|Object > cybox|Properties > APIObj|Function_Name:contains(?CDrawPoly::Serialize))");
		String functionName = function.select("cybox|Observable > cybox|Object > cybox|Properties > APIObj|Function_Name").text();
		assertEquals(functionName, "?CDrawPoly::Serialize");
		source = function.select("cybox|Observable > cybox|Observable_Source > cyboxCommon|Information_Source_Type").text();
		assertEquals(source, "CNN");

		System.out.println("Testing Vulnerability ...");
		Elements vulnerability = doc.select("stixCommon|Exploit_Target:has(et|Vulnerability:has(et|CVE_ID:contains(CVE-2014-1234))");
		String vulnerabilityName = vulnerability.select("stixCommon|Exploit_Target > et|Vulnerability > et|CVE_ID").text();
		assertEquals(vulnerabilityName, "CVE-2014-1234");
		source = vulnerability.select("stixCommon|Exploit_Target > et|Vulnerability > et|source").text();
		assertEquals(source, "CNN");

		System.out.println(("Testing Vulnerability -> File ..."));
		String fileId = file.attr("id");
		String idref = vulnerability.select("stixCommon|Exploit_Target > et|Vulnerability > et|Affected_Software > et|Affected_Software > stixcommon|Observable[idref = " + fileId + "]").attr("idref");
		assertEquals(idref, fileId);

		System.out.println("Testing Vulnerability -> Software ...");
		String softwareId = software.attr("id");
		idref = vulnerability.select("stixCommon|Exploit_Target > et|Vulnerability > et|Affected_Software > et|Affected_Software > stixcommon|Observable[idref = " + softwareId + "]").attr("idref");
		assertEquals(idref, softwareId);

		System.out.println("Testing Vulnerability ...");
		vulnerability = doc.select("stixCommon|Exploit_Target:has(et|Vulnerability:has(et|Description:contains(cross-site scripting))");
		source = vulnerability.select("stixCommon|Exploit_Target > et|Vulnerability > et|source").text();
		assertEquals(source, "CNN");

		System.out.println("Testing Vulnerability -> Software ...");
		idref = vulnerability.select("stixCommon|Exploit_Target > et|Vulnerability > et|Affected_Software > et|Affected_Software > stixcommon|Observable[idref = " + softwareId + "]").attr("idref");
		assertEquals(idref, softwareId);

		System.out.println("Testing Vulnerability");
		vulnerability = doc.select("stixCommon|Exploit_Target:has(et|Vulnerability:has(et|Short_Description:contains(MS15-035))");
		source = vulnerability.select("stixCommon|Exploit_Target > et|Vulnerability > et|source").text();
		assertEquals(source, "CNN");
		assertTrue(true);

		System.out.print("Testing Software - > File");
		idref = software.select("cybox|Observable > cybox|Object > cybox|Related_Objects > cybox|Related_Object").attr("idref");
		assertEquals(idref, fileId);
	}
}
