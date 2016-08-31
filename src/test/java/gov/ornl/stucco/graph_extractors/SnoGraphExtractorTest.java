package gov.ornl.stucco.graph_extractors;

import gov.ornl.stucco.utils.STIXUtils;
import gov.ornl.stucco.utils.ExtractorUtils;

import java.util.Set;

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
 * Unit test for Sno Extractor. 
 */
public class SnoGraphExtractorTest	 extends STIXUtils { 	
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
	 * Test empty document
	 */
	@Test
	public void test_empty_document()	{
		System.out.println();
		System.out.println("STIXExtractor.SnoGraphExtractorTest.test_empty_document()");

		String snoInfo = "file_name,rec_num,timet,site,proto,saddr,daddr,sport,dport,alert_id,alert_rev,alert_msg,icmp_type,icmp_code,gen_id,scountrycode,sorganization,slat,slong,dcountrycode,dorganization,dlat,dlong,distance";

		SnoGraphExtractor snoExtractor = new SnoGraphExtractor(snoInfo);
		JSONObject graph = snoExtractor.getGraph();
		
		System.out.println("Testing that graph is null");
		assertNull(graph);
	}

	/**
	 * Test one entry with ipv6 
	 */
	@Test
	public void test_one_element_with_ipv6()	{

		System.out.println();
		System.out.println("STIXExtractor.SnoGraphExtractorTest.test_one_element_with_ipv6()");

		String snoInfo = "file_name,rec_num,timet,site,proto,saddr,daddr,sport,dport,alert_id,alert_rev,alert_msg,icmp_type,icmp_code,gen_id,scountrycode,sorganization,slat,slong,dcountrycode,dorganization,dlat,dlong,distance\n" + 
		",15107,2016-08-02T19:50:01.111759Z,,6,2002:8214:fa8d:0000:0000:0000:8214:fa8d,2001:05a0:3e01:0000:0000:0000:426e:21ba,55747,80,4000095,1,US-CERT-InBound IPv6 traffic,0,0,1,US," +
		"internet assigned numbers authority,33.98551,-118.45318,US,technologies,42.3636,-71.08521,2602.297137936606";

		SnoGraphExtractor snoExtractor = new SnoGraphExtractor(snoInfo);
		JSONObject graph = snoExtractor.getGraph();
		
		System.out.println("Testing that graph is null");
		assertNull(graph);
	}

	/**
	 * Test one entry  
	 */
	@Test
	public void test_one_element()	{
		try {
			System.out.println();
			System.out.println("STIXExtractor.SnoGraphExtractorTest.test_one_element()");

			String snoInfo = "file_name,rec_num,timet,site,proto,saddr,daddr,sport,dport,alert_id,alert_rev,alert_msg,icmp_type,icmp_code,gen_id,scountrycode,sorganization,slat,slong,dcountrycode,dorganization,dlat,dlong,distance\n" + 
			",15108,2016-08-02T19:50:01.233718Z,pnnl01,1,130.20.177.211,130.20.64.56,0,0,466,5,ICMP L3retriever Ping,8,0,1,US,northwest,46.28583,-119.28333,US,northwest,46.28583,-119.28333,0.0";

			SnoGraphExtractor snoExtractor = new SnoGraphExtractor(snoInfo);
			JSONObject graph = snoExtractor.getGraph();


			JSONObject vertices = graph.getJSONObject("vertices");
			JSONArray edges = graph.getJSONArray("edges");

			System.out.println("Testing IP ... ");
			JSONObject ipJson = getVertByName("130.20.177.211", vertices);
			assertEquals(ipJson.get("vertexType"), "IP");
			assertEquals(ipJson.get("description").toString(), "[130.20.177.211]");
			assertEquals(ipJson.get("ipInt"), ExtractorUtils.ipToLong("130.20.177.211"));
			assertEquals(ipJson.get("source").toString(), "[Sno]");
			assertEquals(ipJson.get("observableType"), "Address");
			String observableString = ipJson.getString("sourceDocument");
			Observable observable = new Observable().fromXMLString(observableString);
			assertTrue(observable.validate());

			System.out.println("Testing IP ... ");
			ipJson = getVertByName("130.20.64.56", vertices);
			assertEquals(ipJson.get("vertexType"), "IP");
			assertEquals(ipJson.get("description").toString(), "[130.20.64.56]");
			assertEquals(ipJson.get("ipInt"), ExtractorUtils.ipToLong("130.20.64.56"));
			assertEquals(ipJson.get("source").toString(), "[Sno]");
			assertEquals(ipJson.get("observableType"), "Address");
			observableString = ipJson.getString("sourceDocument");
			observable = new Observable().fromXMLString(observableString);
			assertTrue(observable.validate());

			System.out.println("Testing Port ... ");
			JSONObject portJson = getVertByName("0", vertices);
			assertEquals(portJson.get("vertexType"), "Observable");
			assertEquals(portJson.get("description").toString(), "[0]");
			assertEquals(portJson.get("source").toString(), "[Sno]");
			assertEquals(portJson.get("observableType"), "Port");
			observableString = portJson.getString("sourceDocument");
			observable = new Observable().fromXMLString(observableString);
			assertTrue(observable.validate());

			System.out.println("Testing Address ... ");
			JSONObject addressJson = getVertByName("130.20.177.211:0", vertices);
			assertEquals(addressJson.get("vertexType"), "Observable");
			assertEquals(addressJson.get("description").toString(), "[130.20.177.211, port 0]");
			assertEquals(addressJson.get("source").toString(), "[Sno]");
			assertEquals(addressJson.get("observableType"), "Socket Address");
			observableString = addressJson.getString("sourceDocument");
			observable = new Observable().fromXMLString(observableString);
			assertTrue(observable.validate());

			System.out.println("Testing Address ... ");
			addressJson = getVertByName("130.20.64.56:0", vertices);
			assertEquals(addressJson.get("vertexType"), "Observable");
			assertEquals(addressJson.get("description").toString(), "[130.20.64.56, port 0]");
			assertEquals(addressJson.get("source").toString(), "[Sno]");
			assertEquals(addressJson.get("observableType"), "Socket Address");
			observableString = addressJson.getString("sourceDocument");
			observable = new Observable().fromXMLString(observableString);
			assertTrue(observable.validate());

			System.out.println("Testing Flow ... ");
			JSONObject flowJson = getVertByName("130.20.177.211:0_through_130.20.64.56:0", vertices);
			assertEquals(flowJson.get("vertexType"), "Observable");
			assertEquals(flowJson.get("description").toString(), "[130.20.177.211, port 0 to 130.20.64.56, port 0]");
			assertEquals(flowJson.get("source").toString(), "[Sno]");
			assertEquals(flowJson.get("observableType"), "Network Flow");
			observableString = flowJson.getString("sourceDocument");
			observable = new Observable().fromXMLString(observableString);
			assertTrue(observable.validate());

			System.out.println("Testing Indicator ... ");
			String indicatorID = getVertIDByType("Indicator", vertices);
			JSONObject indicatorJson = vertices.getJSONObject(indicatorID);
			assertEquals(indicatorJson.get("vertexType"), "Indicator");
			assertEquals(indicatorJson.get("description").toString(), "[ICMP L3retriever Ping]");
			assertEquals(indicatorJson.get("source").toString(), "[Sno]");
			assertTrue(((Set) indicatorJson.get("alias")).contains("466"));
			assertTrue(((Set) indicatorJson.get("alias")).contains("130.20.177.211:0_through_130.20.64.56:0"));
			String indicatorString = indicatorJson.getString("sourceDocument");
			Indicator indicator = new Indicator().fromXMLString(indicatorString);
			assertTrue(indicator.validate());

			System.out.println("Testing Address -> IP ... ");
			String addressID = getVertIDByName("130.20.177.211:0", vertices);
			String ipID = getVertIDByName("130.20.177.211", vertices);
			JSONObject expectedEdge = getEdgeByProps(addressID, ipID, "Sub-Observable", edges);
			assertNotNull(expectedEdge); 

			System.out.println("Testing Address -> Port ... ");
			addressID = getVertIDByName("130.20.177.211:0", vertices);
			String portID = getVertIDByName("0", vertices);
			expectedEdge = getEdgeByProps(addressID, portID, "Sub-Observable", edges);
			assertNotNull(expectedEdge);

			System.out.println("Testing Address -> IP ... ");
			addressID = getVertIDByName("130.20.64.56:0", vertices);
			ipID = getVertIDByName("130.20.64.56", vertices);
			expectedEdge = getEdgeByProps(addressID, ipID, "Sub-Observable", edges);
			assertNotNull(expectedEdge); 

			System.out.println("Testing Address -> Port ... ");
			addressID = getVertIDByName("130.20.64.56:0", vertices);
			portID = getVertIDByName("0", vertices);
			expectedEdge = getEdgeByProps(addressID, portID, "Sub-Observable", edges);
			assertNotNull(expectedEdge);

			System.out.println("Testing Flow -> Src Address ... ");
			String flowID = getVertIDByName("130.20.177.211:0_through_130.20.64.56:0", vertices);
			addressID = getVertIDByName("130.20.177.211:0", vertices);
			expectedEdge = getEdgeByProps(flowID, addressID, "Sub-Observable", edges);
			assertNotNull(expectedEdge); 

			System.out.println("Testing Flow -> Dst Address ... ");
			flowID = getVertIDByName("130.20.177.211:0_through_130.20.64.56:0", vertices);
			addressID = getVertIDByName("130.20.64.56:0", vertices);
			expectedEdge = getEdgeByProps(flowID, addressID, "Sub-Observable", edges);
			assertNotNull(expectedEdge); 

			System.out.println("Testing Indicator -> Flow ... ");
			flowID = getVertIDByName("130.20.177.211:0_through_130.20.64.56:0", vertices);
			expectedEdge = getEdgeByProps(indicatorID, flowID, "Observable", edges);
			assertNotNull(expectedEdge); 

		} catch (SAXException e) {
			e.printStackTrace();
		}
	}
}