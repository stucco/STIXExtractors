package gov.ornl.stucco.graph_extractors;

import java.util.Collection;

import gov.ornl.stucco.utils.STIXUtils;
import gov.ornl.stucco.utils.ExtractorUtils;

import java.io.IOException;

import org.mitre.cybox.cybox_2.Observable;

import org.xml.sax.SAXException;

import org.junit.Test;

import org.json.JSONObject;
import org.json.JSONArray;

import static org.junit.Assert.*;

/**
 * Unit test for HTTPDataGraphExtractor.
 */
public class HTTPRDataGraphExtractorTest extends STIXUtils {

	private JSONObject getVertByName(String name, JSONObject vertices) {
		for (Object key : vertices.keySet()) {
			JSONObject vert = vertices.getJSONObject(key.toString());
			if (name.equals(vert.getString("name"))) {
				return vert;
			}
		}

		return null;
	}

	private String getVertIDByName(String name, JSONObject vertices) {
		for (Object key : vertices.keySet()) { 
			JSONObject vert = vertices.getJSONObject(key.toString());
			if (name.equals(vert.getString("name"))) {
				return key.toString();
			}
		}

		return null;
	}

	private JSONObject getEdgeByProps(String outVertID, String inVertID, String relation, JSONArray edges) {
		for (int i = 0; i < edges.length(); i++) {
			JSONObject edge = edges.getJSONObject(i);
			if (outVertID.equals(edge.getString("outVertID")) && inVertID.equals(edge.getString("inVertID")) && relation.equals(edge.getString("relation"))) {
				return edge;
			}
		}

		return null;
	}

	private boolean compareVertProperties(JSONObject receivedVert, JSONObject expectedVert) {
		boolean equals = true;
		for (Object property : expectedVert.keySet()) {
			if (!receivedVert.has(property.toString())) {
				System.out.println("ERROR: expected property = " + property + " is not found!");
				equals = false;
			}
		}

		return equals;
	}

	/**
	 * Test empty document
	 */
	@Test
	public void test_empty_doc() {
		System.out.println();
		System.out.println("STIXExtractor.HTTPDataExtractorTest.test_empty_doc()");

		String httpInfo = "";

		HTTPRDataGraphExtractor httpGraphExtractor = new HTTPRDataGraphExtractor(httpInfo);
		JSONObject receivedGraph = httpGraphExtractor.getGraph();

		System.out.println("Testing that Graph is null");
		assertNull(receivedGraph);
	}

	/**
	 * Test one entry
	 */
	@Test
	public void test_one_entry() {
		System.out.println();
		System.out.println("STIXExtractor.HTTPDataExtractorTest.test_empty_doc()");

		String httpInfo = "filename,recnum,file_type,amp_version,site,saddr,daddr,request_len,dport,times_seen,first_seen,last_seen,raw_header," +
			"method,uri,proto,terms,bad,headers,accept_language,accept_encoding,accept_charset,user_agent,host,referer,scc,sorg,slat,slon,dcc,dorg,dlat,dlon,distance\n" +
			"20160802193831-pnnl01-ampHttpR4-1.dat,9418,1,2,pnnl01,130.20.249.18,130.20.67.169,157,80,1,2016-08-02 19:23:33,2016-08-02 19:23:33," +
			"HEAD /SMS_DP_SMSPKG$/6249ada8-c6de-4e2d-b84b-bfb116b7055e/sccm?/AM_Delta_Patch_1.225.2944.0.exe HTTP/1.1 User-Agent: Microsoft BITS/7.7 Host: capone.pnl.gov," +
			"HEAD,/SMS_DP_SMSPKG$/6249ada8-c6de-4e2d-b84b-bfb116b7055e/sccm?/AM_Delta_Patch_1.225.2944.0.exe,HTTP/1.1,,,user-agent host,,,,Microsoft BITS/7.7,capone.pnl.gov," +
			"referer.com,US,pacific northwest national laboratory,46.28583,-119.28333,US,pacific northwest national laboratory,46.28583,-119.28333,0.0";


		HTTPRDataGraphExtractor httprGraphExtractor = new HTTPRDataGraphExtractor(httpInfo);
		JSONObject graph = httprGraphExtractor.getGraph();
		JSONObject vertices = graph.getJSONObject("vertices");
		JSONArray edges = graph.getJSONArray("edges");
		
		System.out.println("Testing IP ... ");
		JSONObject receivedIP = getVertByName("130.20.249.18", vertices);
		assertEquals(receivedIP.getString("vertexType"), "IP");
		assertTrue(((Collection)receivedIP.get("description")).contains("130.20.249.18"));
		assertEquals(receivedIP.get("ipInt"), ExtractorUtils.ipToLong("130.20.249.18"));
		assertTrue(((Collection)receivedIP.get("source")).contains("HTTPRequest"));
		assertEquals(receivedIP.getString("observableType"), "Address");
		String sourceDocument = receivedIP.getString("sourceDocument");
		try {
			Observable sourceObservable = new Observable().fromXMLString(sourceDocument);
			assertTrue(sourceObservable.validate());
		} catch (SAXException e) {
			e.printStackTrace();
		}

		System.out.println("Testing IP ... ");
		receivedIP = getVertByName("130.20.67.169", vertices);
		assertEquals(receivedIP.getString("vertexType"), "IP");
		assertTrue(((Collection)receivedIP.get("description")).contains("130.20.67.169"));
		assertEquals(receivedIP.get("ipInt"), ExtractorUtils.ipToLong("130.20.67.169"));
		assertTrue(((Collection)receivedIP.get("source")).contains("HTTPRequest"));
		assertEquals(receivedIP.getString("observableType"), "Address");
		sourceDocument = receivedIP.getString("sourceDocument");
		try {
			Observable sourceObservable = new Observable().fromXMLString(sourceDocument);
			assertTrue(sourceObservable.validate());
		} catch (SAXException e) {
			e.printStackTrace();
		}

		System.out.println("Testing Port ... ");
		JSONObject receivedPort = getVertByName("80", vertices);
		assertEquals(receivedPort.getString("vertexType"), "Observable");
		assertTrue(((Collection)receivedPort.get("description")).contains("80"));
		assertTrue(((Collection)receivedPort.get("source")).contains("HTTPRequest"));
		assertEquals(receivedPort.getString("observableType"), "Port");
		sourceDocument = receivedPort.getString("sourceDocument");
		try {
			Observable sourceObservable = new Observable().fromXMLString(sourceDocument);
			assertTrue(sourceObservable.validate());
		} catch (SAXException e) {
			e.printStackTrace();
		}

		System.out.println("Testing Requested URI ... ");
		JSONObject receivedURI = getVertByName("/SMS_DP_SMSPKG$/6249ada8-c6de-4e2d-b84b-bfb116b7055e/sccm?/AM_Delta_Patch_1.225.2944.0.exe", vertices);
		assertEquals(receivedURI.getString("vertexType"), "Observable");
		assertTrue(((Collection)receivedURI.get("description")).contains("/SMS_DP_SMSPKG$/6249ada8-c6de-4e2d-b84b-bfb116b7055e/sccm?/AM_Delta_Patch_1.225.2944.0.exe"));
		assertTrue(((Collection)receivedURI.get("source")).contains("HTTPRequest"));
		assertEquals(receivedURI.getString("observableType"), "URI");
		sourceDocument = receivedURI.getString("sourceDocument");
		try {
			Observable sourceObservable = new Observable().fromXMLString(sourceDocument);
			assertTrue(sourceObservable.validate());
		} catch (SAXException e) {
			e.printStackTrace();
		}
		
		System.out.println("Testing Referer URI ... ");
		JSONObject refererURI = getVertByName("referer.com", vertices);
		assertEquals(refererURI.getString("vertexType"), "Observable");
		assertTrue(((Collection)refererURI.get("description")).contains("referer.com"));
		assertTrue(((Collection)refererURI.get("source")).contains("HTTPRequest"));
		assertEquals(refererURI.getString("observableType"), "URI");
		sourceDocument = refererURI.getString("sourceDocument");
		try {
			Observable sourceObservable = new Observable().fromXMLString(sourceDocument);
			assertTrue(sourceObservable.validate());
		} catch (SAXException e) {
			e.printStackTrace();
		}

		System.out.println("Testing Domain Name ... ");
		JSONObject receivedDNS = getVertByName("capone.pnl.gov", vertices);
		assertEquals(receivedDNS.getString("vertexType"), "Observable");
		assertTrue(((Collection)receivedDNS.get("description")).contains("capone.pnl.gov"));
		assertTrue(((Collection)receivedDNS.get("source")).contains("HTTPRequest"));
		assertEquals(receivedDNS.getString("observableType"), "Domain Name");
		sourceDocument = receivedDNS.getString("sourceDocument");
		try {
			Observable sourceObservable = new Observable().fromXMLString(sourceDocument);
			assertTrue(sourceObservable.validate());
		} catch (SAXException e) {
			e.printStackTrace();
		}

		System.out.println("Testing HTTP Request ... ");
		JSONObject receivedHTTP = getVertByName("HEAD /SMS_DP_SMSPKG$/6249ada8-c6de-4e2d-b84b-bfb116b7055e/sccm?/AM_Delta_Patch_1.225.2944.0.exe HTTP/1.1 User-Agent: Microsoft BITS/7.7 Host: capone.pnl.gov", vertices);
		assertEquals(receivedHTTP.getString("vertexType"), "Observable");
		System.out.println(receivedHTTP.get("description"));
		assertTrue(((Collection)receivedHTTP.get("description")).contains("HTTP request: HEAD /SMS_DP_SMSPKG$/6249ada8-c6de-4e2d-b84b-bfb116b7055e/sccm?/AM_Delta_Patch_1.225.2944.0.exe HTTP/1.1 User-Agent: Microsoft BITS/7.7 Host: capone.pnl.gov"));
		assertTrue(((Collection)receivedHTTP.get("source")).contains("HTTPRequest"));
		assertEquals(receivedHTTP.getString("observableType"), "HTTP Session");
		sourceDocument = receivedHTTP.getString("sourceDocument");
		try {
			Observable sourceObservable = new Observable().fromXMLString(sourceDocument);
			assertTrue(sourceObservable.validate());
		} catch (SAXException e) {
			e.printStackTrace();
		}

		System.out.println("Testing HTTP Session -> IP ... ");
		String httpID = getVertIDByName("HEAD /SMS_DP_SMSPKG$/6249ada8-c6de-4e2d-b84b-bfb116b7055e/sccm?/AM_Delta_Patch_1.225.2944.0.exe HTTP/1.1 User-Agent: Microsoft BITS/7.7 Host: capone.pnl.gov", vertices);
		String addressID = getVertIDByName("130.20.249.18", vertices);
		JSONObject expectedEdge = getEdgeByProps(httpID, addressID, "Sub-Observable", edges);
		assertNotNull(expectedEdge); 

		System.out.println("Testing HTTP Session -> Domain Name ... ");
		httpID = getVertIDByName("HEAD /SMS_DP_SMSPKG$/6249ada8-c6de-4e2d-b84b-bfb116b7055e/sccm?/AM_Delta_Patch_1.225.2944.0.exe HTTP/1.1 User-Agent: Microsoft BITS/7.7 Host: capone.pnl.gov", vertices);
		String dnsID = getVertIDByName("capone.pnl.gov", vertices);
		expectedEdge = getEdgeByProps(httpID, dnsID, "Sub-Observable", edges);
		assertNotNull(expectedEdge); 

		System.out.println("Testing HTTP Session -> Port ... ");
		httpID = getVertIDByName("HEAD /SMS_DP_SMSPKG$/6249ada8-c6de-4e2d-b84b-bfb116b7055e/sccm?/AM_Delta_Patch_1.225.2944.0.exe HTTP/1.1 User-Agent: Microsoft BITS/7.7 Host: capone.pnl.gov", vertices);
		String portID = getVertIDByName("80", vertices);
		expectedEdge = getEdgeByProps(httpID, portID, "Sub-Observable", edges);
		assertNotNull(expectedEdge); 

		System.out.println("Testing HTTP Session -> URI ... ");
		httpID = getVertIDByName("HEAD /SMS_DP_SMSPKG$/6249ada8-c6de-4e2d-b84b-bfb116b7055e/sccm?/AM_Delta_Patch_1.225.2944.0.exe HTTP/1.1 User-Agent: Microsoft BITS/7.7 Host: capone.pnl.gov", vertices);
		String uriID = getVertIDByName("/SMS_DP_SMSPKG$/6249ada8-c6de-4e2d-b84b-bfb116b7055e/sccm?/AM_Delta_Patch_1.225.2944.0.exe", vertices);
		expectedEdge = getEdgeByProps(httpID, uriID, "Sub-Observable", edges);
		assertNotNull(expectedEdge); 

		System.out.println("Testing HTTP Session -> Referer URI ... ");
		httpID = getVertIDByName("HEAD /SMS_DP_SMSPKG$/6249ada8-c6de-4e2d-b84b-bfb116b7055e/sccm?/AM_Delta_Patch_1.225.2944.0.exe HTTP/1.1 User-Agent: Microsoft BITS/7.7 Host: capone.pnl.gov", vertices);
		String refererID = getVertIDByName("referer.com", vertices);
		expectedEdge = getEdgeByProps(httpID, refererID, "Sub-Observable", edges);
		assertNotNull(expectedEdge); 

		System.out.println("Testing Domain Name -> IP ... ");
		dnsID = getVertIDByName("capone.pnl.gov", vertices);
		String ipID = getVertIDByName("130.20.67.169", vertices);
		expectedEdge = getEdgeByProps(dnsID, ipID, "Sub-Observable", edges);
		assertNotNull(expectedEdge); 
	}
}
