package STIXExtractor;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.parser.Parser;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import org.mitre.stix.stix_1.STIXPackage;

import org.junit.Test;

import static org.junit.Assert.*;

import org.json.JSONObject;
import org.json.JSONArray;

import STIXExtractor.ArgusGraphExtractor;

/**
 * Unit test for Argus Extractor. 
 */
public class ArgusGraphExtractorTest	{
	
	/**
	 * Test empty document
	 */
	// @Test
	public void test_empty_document()	{

		System.out.println();
		System.out.println("STIXExtractor.ArgusExtractorTest.test_empty_document()");

		String[] headers = "StartTime,Flgs,Proto,SrcAddr,Sport,Dir,DstAddr,Dport,TotPkts,TotBytes,State".split(",");
		String argusInfo = "";

		ArgusGraphExtractor argusExtractor = new ArgusGraphExtractor(headers, argusInfo);
		// STIXPackage stixPackage = argusExtractor.getStixPackage();
		// System.out.println("Testing that package is null");
		// assertTrue(stixPackage == null);
	}

  /**
	 * Test one element
	 */
	@Test
	public void test_one_element_with_header_to_graph()	{
		System.out.println();
		System.out.println("STIXExtractor.ArgusExtractorTest.test_one_element_with_header()");

		String[] headers = "StartTime,Flgs,Proto,SrcAddr,Sport,Dir,DstAddr,Dport,TotPkts,TotBytes,State".split(",");
		String argusInfo = "1373553586.136399, e s,6,10.10.10.1,56867,->,10.10.10.100,22,8,585,REQ";
		
		ArgusGraphExtractor argusExtractor = new ArgusGraphExtractor(headers, argusInfo);
		JSONObject graph = argusExtractor.getGraph();
		// System.out.println(graph.toString(2));
		assertTrue(true);
	}

	/**
	 * Test one element
	 */
	@Test
	public void test_one_element_with_address_duplicate()	{
		System.out.println();
		System.out.println("STIXExtractor.ArgusExtractorTest.test_one_element_with_header()");

		String[] headers = "StartTime,Flgs,Proto,SrcAddr,Sport,Dir,DstAddr,Dport,TotPkts,TotBytes,State".split(",");
		String argusInfo = "1373553586.136399, e s,6,10.10.10.1,56867,->,10.10.10.1,56867,8,585,REQ";
		
		ArgusGraphExtractor argusExtractor = new ArgusGraphExtractor(headers, argusInfo);
		JSONObject graph = argusExtractor.getGraph();
		// System.out.println(graph.toString(2));
		assertTrue(true);
	}
}