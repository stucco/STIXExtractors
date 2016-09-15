package gov.ornl.stucco.graph_extractors;

import gov.ornl.stucco.utils.STIXUtils;
import gov.ornl.stucco.utils.ExtractorUtils;
import gov.ornl.stucco.graph_extractors.BannerGraphExtractor;

import java.util.Set;
import java.util.Collection;

import org.mitre.cybox.cybox_2.Observable;

import org.xml.sax.SAXException;

import org.junit.Test;

import static org.junit.Assert.*;

import org.json.JSONObject;
import org.json.JSONArray;

import  org.mitre.stix.indicator_2.*;
import org.mitre.stix.common_1.StructuredTextType;
import org.mitre.stix.common_1.InformationSourceType;
import org.mitre.stix.common_1.IdentityType;
import javax.xml.namespace.QName;

import java.util.GregorianCalendar;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.namespace.QName;				
import javax.xml.datatype.DatatypeConfigurationException;

/**
 * Unit test for Banner Extractor. 
 */
public class BannerGraphExtractorTest	 extends STIXUtils { 	
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

	private String getVertIDByType(String vertexType, JSONObject vertices) {
		for (Object key : vertices.keySet()) {
			JSONObject vert = vertices.getJSONObject(key.toString());
			if (vertexType.equals(vert.getString("vertexType"))) {
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

	private long convertTimestamp(String time) { 
		if (time.endsWith("Z")) {
			return convertTimestamp(time.replaceAll("Z$", "+0000"), "yyyy-MM-dd'T'HH:mm:ss.SSSZ");
		} else {
			return convertTimestamp(time, "yyyy-MM-dd'T'HH:mm:ss.SSSXXX");
		}
	}

	/**
	 * Test empty element
	 */
	@Test
	public void test_empty_element() {
			
		System.out.println();
		System.out.println("gov.ornl.stucco.graph_extractors.BannerGraphExtractor.test_empty_element()");

		String bannerInfo = 
			"filename,recnum,file_type,amp_version,site,banner,addr,app_protocol,times_seen,first_seen,last_seen,cc,org,lat,lon\n" +
			",,,,,,,,,,,,,,";

		BannerGraphExtractor bannerExtractor = new BannerGraphExtractor(bannerInfo);
		JSONObject graph = bannerExtractor.getGraph();

		System.out.println("Testing that STIXPackage is null");
		assertTrue(graph == null);
	}

	/**
	 * Test one element
	 */
	@Test
	public void test_one_element_with_header() throws SAXException {
			
		System.out.println();
		System.out.println("gov.ornl.stucco.graph_extractors.BannerGraphExtractor.test_one_element_with_header()");

		String bannerInfo = 
			"filename,recnum,file_type,amp_version,site,banner,addr,server_port,app_protocol,times_seen,first_seen,last_seen,cc,org,lat,lon\n" +
			"20160803152157-site-ampBanS4-1.dat,32474,6,2,site,Apache,64.90.41.213,80,80,20,2016-08-03 15:06:58,2016-08-03 15:06:58,US,new dream network llc,33.91787,-117.89075";

		BannerGraphExtractor bannerExtractor = new BannerGraphExtractor(bannerInfo);
		JSONObject graph = bannerExtractor.getGraph();

		JSONObject vertices = graph.getJSONObject("vertices");
		JSONArray edges = graph.getJSONArray("edges");

		System.out.println("Testing IP ... ");
		JSONObject ipJson = getVertByName("64.90.41.213", vertices);
		assertEquals(ipJson.get("vertexType"), "IP");
		assertEquals(ipJson.get("description").toString(), "[64.90.41.213]");
		assertEquals(ipJson.get("ipInt"), ExtractorUtils.ipToLong("64.90.41.213"));
		assertEquals(ipJson.get("source").toString(), "[Banner]");
		assertEquals(ipJson.get("observableType"), "Address");
		String observableString = ipJson.getString("sourceDocument");
		try {
			Observable sourceObservable = new Observable().fromXMLString(observableString);
			assertTrue(sourceObservable.validate());
		} catch (SAXException e) {
			e.printStackTrace();
		}

		System.out.println("Testing Port ... ");
		JSONObject portJson = getVertByName("80", vertices);
		assertEquals(portJson.get("vertexType"), "Observable");
		assertEquals(portJson.get("description").toString(), "[80]");
		assertEquals(portJson.get("source").toString(), "[Banner]");
		assertEquals(portJson.get("observableType"), "Port");
		observableString = ipJson.getString("sourceDocument");
		try {
			Observable sourceObservable = new Observable().fromXMLString(observableString);
			assertTrue(sourceObservable.validate());
		} catch (SAXException e) {
			e.printStackTrace();
		}

		System.out.println("Testing Address ... ");
		JSONObject addressJson = getVertByName("64.90.41.213:80", vertices);
		assertEquals(addressJson.get("vertexType"), "Observable");
		assertEquals(addressJson.get("description").toString(), "[64.90.41.213, port 80]");
		assertEquals(addressJson.get("source").toString(), "[Banner]");
		assertEquals(addressJson.get("observableType"), "Socket Address");
		observableString = addressJson.getString("sourceDocument");
		try {
			Observable sourceObservable = new Observable().fromXMLString(observableString);
			assertTrue(sourceObservable.validate());
		} catch (SAXException e) {
			e.printStackTrace();
		}

		System.out.println("Testing Address -> IP ... ");
		String addressID = getVertIDByName("64.90.41.213:80", vertices);
		String ipID = getVertIDByName("64.90.41.213", vertices);
		JSONObject expectedEdge = getEdgeByProps(addressID, ipID, "Sub-Observable", edges);
		assertNotNull(expectedEdge); 

		System.out.println("Testing Address -> Port ... ");
		String portID = getVertIDByName("80", vertices);
		expectedEdge = getEdgeByProps(addressID, portID, "Sub-Observable", edges);
		assertNotNull(expectedEdge);
	}

		/**
	 * Test one element
	 */
	@Test
	public void test_two_elements_with_header_and_duplicates() throws SAXException {
			
		System.out.println();
		System.out.println("gov.ornl.stucco.graph_extractors.BannerGraphExtractor.test_two_elements_with_header_and_duplicates()");

		String bannerInfo = 
			"filename,recnum,file_type,amp_version,site,banner,addr,server_port,app_protocol,times_seen,first_seen,last_seen,cc,org,lat,lon\n" +
			"20160803152157-site-ampBanS4-1.dat,32474,6,2,site,Apache,64.90.41.213,80,80,20,2016-08-03 15:06:58,2016-08-03 15:06:58,US,new dream network llc,33.91787,-117.89075\n" +
			"20160803152157-site-ampBanS4-1.dat,32474,6,2,site,Apache,0.0.0.0,80,80,20,2016-08-03 15:06:58,2016-08-03 15:06:58,US,new dream network llc,33.91787,-117.89075";

		BannerGraphExtractor bannerExtractor = new BannerGraphExtractor(bannerInfo);
		JSONObject graph = bannerExtractor.getGraph();

		JSONObject vertices = graph.getJSONObject("vertices");
		JSONArray edges = graph.getJSONArray("edges");

		assertEquals(vertices.length(), 5);
		assertEquals(edges.length(), 4);

		System.out.println("Testing IP ... ");
		JSONObject ipJson = getVertByName("64.90.41.213", vertices);
		assertEquals(ipJson.get("vertexType"), "IP");
		assertEquals(ipJson.get("description").toString(), "[64.90.41.213]");
		assertEquals(ipJson.get("ipInt"), ExtractorUtils.ipToLong("64.90.41.213"));
		assertEquals(ipJson.get("source").toString(), "[Banner]");
		assertEquals(ipJson.get("observableType"), "Address");
		String observableString = ipJson.getString("sourceDocument");
		try {
			Observable sourceObservable = new Observable().fromXMLString(observableString);
			assertTrue(sourceObservable.validate());
		} catch (SAXException e) {
			e.printStackTrace();
		}

		System.out.println("Testing Port ... ");
		JSONObject portJson = getVertByName("80", vertices);
		assertEquals(portJson.get("vertexType"), "Observable");
		assertEquals(portJson.get("description").toString(), "[80]");
		assertEquals(portJson.get("source").toString(), "[Banner]");
		assertEquals(portJson.get("observableType"), "Port");
		observableString = ipJson.getString("sourceDocument");
		try {
			Observable sourceObservable = new Observable().fromXMLString(observableString);
			assertTrue(sourceObservable.validate());
		} catch (SAXException e) {
			e.printStackTrace();
		}

		System.out.println("Testing Address ... ");
		JSONObject addressJson = getVertByName("64.90.41.213:80", vertices);
		assertEquals(addressJson.get("vertexType"), "Observable");
		assertEquals(addressJson.get("description").toString(), "[64.90.41.213, port 80]");
		assertEquals(addressJson.get("source").toString(), "[Banner]");
		assertEquals(addressJson.get("observableType"), "Socket Address");
		observableString = addressJson.getString("sourceDocument");
		try {
			Observable sourceObservable = new Observable().fromXMLString(observableString);
			assertTrue(sourceObservable.validate());
		} catch (SAXException e) {
			e.printStackTrace();
		}

		System.out.println("Testing Address -> IP ... ");
		String addressID = getVertIDByName("64.90.41.213:80", vertices);
		String ipID = getVertIDByName("64.90.41.213", vertices);
		JSONObject expectedEdge = getEdgeByProps(addressID, ipID, "Sub-Observable", edges);
		assertNotNull(expectedEdge); 

		System.out.println("Testing Address -> Port ... ");
		String portID = getVertIDByName("80", vertices);
		expectedEdge = getEdgeByProps(addressID, portID, "Sub-Observable", edges);
		assertNotNull(expectedEdge);

		System.out.println("Testing IP ... ");
		ipJson = getVertByName("0.0.0.0", vertices);
		assertEquals(ipJson.get("vertexType"), "IP");
		assertEquals(ipJson.get("description").toString(), "[0.0.0.0]");
		assertEquals(ipJson.get("ipInt"), ExtractorUtils.ipToLong("0.0.0.0"));
		assertEquals(ipJson.get("source").toString(), "[Banner]");
		assertEquals(ipJson.get("observableType"), "Address");
		observableString = ipJson.getString("sourceDocument");
		try {
			Observable sourceObservable = new Observable().fromXMLString(observableString);
			assertTrue(sourceObservable.validate());
		} catch (SAXException e) {
			e.printStackTrace();
		}

		System.out.println("Testing Address ... ");
		addressJson = getVertByName("0.0.0.0:80", vertices);
		assertEquals(addressJson.get("vertexType"), "Observable");
		assertEquals(addressJson.get("description").toString(), "[0.0.0.0, port 80]");
		assertEquals(addressJson.get("source").toString(), "[Banner]");
		assertEquals(addressJson.get("observableType"), "Socket Address");
		observableString = addressJson.getString("sourceDocument");
		try {
			Observable sourceObservable = new Observable().fromXMLString(observableString);
			assertTrue(sourceObservable.validate());
		} catch (SAXException e) {
			e.printStackTrace();
		}

		System.out.println("Testing Address -> IP ... ");
		addressID = getVertIDByName("0.0.0.0:80", vertices);
		ipID = getVertIDByName("0.0.0.0", vertices);
		expectedEdge = getEdgeByProps(addressID, ipID, "Sub-Observable", edges);
		assertNotNull(expectedEdge); 

		System.out.println("Testing Address -> Port ... ");
		portID = getVertIDByName("80", vertices);
		expectedEdge = getEdgeByProps(addressID, portID, "Sub-Observable", edges);
		assertNotNull(expectedEdge);
	}
}