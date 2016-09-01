package gov.ornl.stucco.graph_extractors;

import gov.ornl.stucco.utils.STIXUtils;

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
			",US,pacific northwest national laboratory,46.28583,-119.28333,US,pacific northwest national laboratory,46.28583,-119.28333,0.0";


		HTTPRDataGraphExtractor httpGraphExtractor = new HTTPRDataGraphExtractor(httpInfo);
		JSONObject receivedGraph = httpGraphExtractor.getGraph();

		assertNotNull(receivedGraph);
	}
}
