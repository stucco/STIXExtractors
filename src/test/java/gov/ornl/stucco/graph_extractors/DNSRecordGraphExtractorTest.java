package gov.ornl.stucco.graph_extractors;

import gov.ornl.stucco.utils.STIXUtils;
import gov.ornl.stucco.utils.ExtractorUtils;
import gov.ornl.stucco.graph_extractors.DNSRecordGraphExtractor;

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
 * Unit test for DNSRecord Extractor. 
 */
public class DNSRecordGraphExtractorTest	 extends STIXUtils { 	
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
	//@Test
	public void test_empty_document()	{
		System.out.println();
		System.out.println("gov.ornl.stucco.graph_extractors.DNSRecordGraphExtractorTest.test_empty_document()");

		String dnsInfo = "file_name,rec_num,timet,site,proto,saddr,daddr,sport,dport,alert_id,alert_rev,alert_msg,icmp_type,icmp_code,gen_id,scountrycode,sorganization,slat,slong,dcountrycode,dorganization,dlat,dlong,distance";

		DNSRecordGraphExtractor DNSRecordExtractor = new DNSRecordGraphExtractor(dnsInfo);
		JSONObject graph = DNSRecordExtractor.getGraph();
		
		System.out.println("Testing that graph is null");
		assertNull(graph);
	}

	/**
	 * Test one entry with ipv6 
	 */
	@Test
	public void test_one_element()	{
		System.out.println("gov.ornl.stucco.graph_extractors.DNSRecordGraphExtractor.test_one_element_with_header()");

		String dnsInfo = 
			"filename,recnum,file_type,amp_version,site,saddr,daddr,ttl,rqtype,flags,rqfqdn,refqdn,raddr,preference," +	
			"answer_ns,authoritative_ns,times_seen,first_seen_timet,last_seen_timet,scountrycode,sorganization,slat,slong," +
			"dcountrycode,dorganization,dlat,dlong,rcountrycode,rorganization,rlat,rlong\n" +
			"20150712000033-ornl-ampDnsN4-1,42513,3,258,ornl,128.219.177.244,68.87.73.245,0,1,17,DALE-PC.ORNL.GOV,haha,89.79.77.77,haha,haha,5n6unsmlboh476,2," +
			"2015-07-12 00:00:27+00,2015-07-12 00:00:27+00,US,oak ridge national laboratory,36.02103,84,US,comcast cable communications inc.," +	
			"38.6741,-77.4243,haha,haha,-91,-181";
	
		DNSRecordGraphExtractor dnsExtractor = new DNSRecordGraphExtractor(dnsInfo);
		JSONObject graph = dnsExtractor.getGraph();


		JSONObject vertices = graph.getJSONObject("vertices");
		JSONArray edges = graph.getJSONArray("edges");

		System.out.println("Tesing Source IP ...");
		JSONObject srcIP = getVertByName("128.219.177.244", vertices);
		assertTrue(((Collection)srcIP.get("description")).contains("128.219.177.244"));
		assertEquals(srcIP.get("ipInt"), ExtractorUtils.ipToLong("128.219.177.244"));
		assertTrue(((Collection)srcIP.get("source")).contains("DNSRecord"));
		assertEquals(srcIP.getString("observableType"), "Address");
		String sourceDocument = srcIP.getString("sourceDocument");
		try {
			Observable sourceObservable = new Observable().fromXMLString(sourceDocument);
			assertTrue(sourceObservable.validate());
		} catch (SAXException e) {
			e.printStackTrace();
		}

		System.out.println("Tesing Destination IP ...");
		JSONObject dstIP = getVertByName("68.87.73.245", vertices);
		assertTrue(((Collection)dstIP.get("description")).contains("68.87.73.245"));
		assertEquals(dstIP.get("ipInt"), ExtractorUtils.ipToLong("68.87.73.245"));
		assertTrue(((Collection)dstIP.get("source")).contains("DNSRecord"));
		assertEquals(dstIP.getString("observableType"), "Address");
		sourceDocument = dstIP.getString("sourceDocument");
		try {
			Observable sourceObservable = new Observable().fromXMLString(sourceDocument);
			assertTrue(sourceObservable.validate());
		} catch (SAXException e) {
			e.printStackTrace();
		}

		System.out.println("Tesing Requested IP ...");
		JSONObject reqIP = getVertByName("89.79.77.77", vertices);
		assertTrue(((Collection)reqIP.get("description")).contains("89.79.77.77"));
		assertEquals(reqIP.get("ipInt"), ExtractorUtils.ipToLong("89.79.77.77"));
		assertTrue(((Collection)reqIP.get("source")).contains("DNSRecord"));
		assertEquals(reqIP.getString("observableType"), "Address");
		sourceDocument = reqIP.getString("sourceDocument");
		try {
			Observable sourceObservable = new Observable().fromXMLString(sourceDocument);
			assertTrue(sourceObservable.validate());
		} catch (SAXException e) {
			e.printStackTrace();
		}

		System.out.println("Testing Domain Name ... ");
		JSONObject reqDNS = getVertByName("DALE-PC.ORNL.GOV", vertices);
		assertEquals(reqDNS.getString("vertexType"), "Observable");
		assertTrue(((Collection)reqDNS.get("description")).contains("DALE-PC.ORNL.GOV"));
		assertTrue(((Collection)reqDNS.get("source")).contains("DNSRecord"));
		assertEquals(reqDNS.getString("observableType"), "Domain Name");
		sourceDocument = reqDNS.getString("sourceDocument");
		try {
			Observable sourceObservable = new Observable().fromXMLString(sourceDocument);
			assertTrue(sourceObservable.validate());
		} catch (SAXException e) {
			e.printStackTrace();
		}

		System.out.println("Testing DNS Record ... ");
		JSONObject dnsRecord = getVertByName("DALE-PC.ORNL.GOV_resolved_to_89.79.77.77", vertices);
		assertEquals(dnsRecord.getString("vertexType"), "Observable");
		assertTrue(((Collection)dnsRecord.get("description")).contains("Requested domain name DALE-PC.ORNL.GOV resolved to IP address 89.79.77.77"));
		assertTrue(((Collection)dnsRecord.get("source")).contains("DNSRecord"));
		assertEquals(dnsRecord.getString("observableType"), "DNS Record");
		sourceDocument = dnsRecord.getString("sourceDocument");
		try {
			Observable sourceObservable = new Observable().fromXMLString(sourceDocument);
			assertTrue(sourceObservable.validate());
		} catch (SAXException e) {
			e.printStackTrace();
		}

		System.out.println("Testing DNS Record -> Domain Name ... ");
		String dnsRecordID = getVertIDByName("DALE-PC.ORNL.GOV_resolved_to_89.79.77.77", vertices);
		String dnsNameID = getVertIDByName("DALE-PC.ORNL.GOV", vertices);
		JSONObject expectedEdge = getEdgeByProps(dnsRecordID, dnsNameID, "Sub-Observable", edges);
		assertNotNull(expectedEdge); 

		System.out.println("Testing DNS Record -> Requested IP ... ");
		dnsRecordID = getVertIDByName("DALE-PC.ORNL.GOV_resolved_to_89.79.77.77", vertices);
		String reqIpID = getVertIDByName("89.79.77.77", vertices);
		expectedEdge = getEdgeByProps(dnsRecordID, reqIpID, "Sub-Observable", edges);
		assertNotNull(expectedEdge);

		System.out.println("Testing DNS Record -> Source IP ... ");
		dnsRecordID = getVertIDByName("DALE-PC.ORNL.GOV_resolved_to_89.79.77.77", vertices);
		String srcIpID = getVertIDByName("128.219.177.244", vertices);
		expectedEdge = getEdgeByProps(dnsRecordID, srcIpID, "Sub-Observable", edges);
		assertNotNull(expectedEdge);

		System.out.println("Testing DNS Record -> Destination IP ... ");
		dnsRecordID = getVertIDByName("DALE-PC.ORNL.GOV_resolved_to_89.79.77.77", vertices);
		String dstIpID = getVertIDByName("68.87.73.245", vertices);
		expectedEdge = getEdgeByProps(dnsRecordID, dstIpID, "Sub-Observable", edges);
		assertNotNull(expectedEdge);
	}

	@Test
	public void testDuplicates() {
		System.out.println("gov.ornl.stucco.graph_extractors.DNSRecordGraphExtractor.test_testDuplicates()");

		String dnsInfo = 
			"20150712000033-ornl-ampDnsN4-1,42513,3,258,ornl,128.219.177.244,68.87.73.245,0,1,17,DALE-PC.ORNL.GOV,haha,89.79.77.77,haha,haha,5n6unsmlboh476,2," +
			"2015-07-12 00:00:27+00,2015-07-12 00:00:27+00,US,oak ridge national laboratory,36.02103,84,US,comcast cable communications inc.," +	
			"38.6741,-77.4243,haha,haha,-91,-181\n" +
			"20150712000033-ornl-ampDnsN4-1,42513,3,258,ornl,128.219.177.244,68.87.73.245,0,1,17,DALE-PC.ORNL.GOV,haha,89.79.77.77,haha,haha,5n6unsmlboh476,2," +
			"2015-07-12 00:00:27+00,2015-07-12 00:00:27+00,US,oak ridge national laboratory,36.02103,84,US,comcast cable communications inc.," +	
			"38.6741,-77.4243,haha,haha,-91,-181";

		DNSRecordGraphExtractor dnsExtractor = new DNSRecordGraphExtractor(dnsInfo);
		JSONObject graph = dnsExtractor.getGraph();

		JSONObject vertices = graph.getJSONObject("vertices");
		assertTrue(vertices.length() == 5);
		JSONArray edges = graph.getJSONArray("edges");
		assertTrue(edges.length() == 4);

		System.out.println("Tesing Source IP ...");
		JSONObject srcIP = getVertByName("128.219.177.244", vertices);
		assertTrue(((Collection)srcIP.get("description")).contains("128.219.177.244"));
		assertEquals(srcIP.get("ipInt"), ExtractorUtils.ipToLong("128.219.177.244"));
		assertTrue(((Collection)srcIP.get("source")).contains("DNSRecord"));
		assertEquals(srcIP.getString("observableType"), "Address");
		String sourceDocument = srcIP.getString("sourceDocument");
		try {
			Observable sourceObservable = new Observable().fromXMLString(sourceDocument);
			assertTrue(sourceObservable.validate());
		} catch (SAXException e) {
			e.printStackTrace();
		}

		System.out.println("Tesing Destination IP ...");
		JSONObject dstIP = getVertByName("68.87.73.245", vertices);
		assertTrue(((Collection)dstIP.get("description")).contains("68.87.73.245"));
		assertEquals(dstIP.get("ipInt"), ExtractorUtils.ipToLong("68.87.73.245"));
		assertTrue(((Collection)dstIP.get("source")).contains("DNSRecord"));
		assertEquals(dstIP.getString("observableType"), "Address");
		sourceDocument = dstIP.getString("sourceDocument");
		try {
			Observable sourceObservable = new Observable().fromXMLString(sourceDocument);
			assertTrue(sourceObservable.validate());
		} catch (SAXException e) {
			e.printStackTrace();
		}

		System.out.println("Tesing Requested IP ...");
		JSONObject reqIP = getVertByName("89.79.77.77", vertices);
		assertTrue(((Collection)reqIP.get("description")).contains("89.79.77.77"));
		assertEquals(reqIP.get("ipInt"), ExtractorUtils.ipToLong("89.79.77.77"));
		assertTrue(((Collection)reqIP.get("source")).contains("DNSRecord"));
		assertEquals(reqIP.getString("observableType"), "Address");
		sourceDocument = reqIP.getString("sourceDocument");
		try {
			Observable sourceObservable = new Observable().fromXMLString(sourceDocument);
			assertTrue(sourceObservable.validate());
		} catch (SAXException e) {
			e.printStackTrace();
		}

		System.out.println("Testing Domain Name ... ");
		JSONObject reqDNS = getVertByName("DALE-PC.ORNL.GOV", vertices);
		assertEquals(reqDNS.getString("vertexType"), "Observable");
		assertTrue(((Collection)reqDNS.get("description")).contains("DALE-PC.ORNL.GOV"));
		assertTrue(((Collection)reqDNS.get("source")).contains("DNSRecord"));
		assertEquals(reqDNS.getString("observableType"), "Domain Name");
		sourceDocument = reqDNS.getString("sourceDocument");
		try {
			Observable sourceObservable = new Observable().fromXMLString(sourceDocument);
			assertTrue(sourceObservable.validate());
		} catch (SAXException e) {
			e.printStackTrace();
		}

		System.out.println("Testing DNS Record ... ");
		JSONObject dnsRecord = getVertByName("DALE-PC.ORNL.GOV_resolved_to_89.79.77.77", vertices);
		assertEquals(dnsRecord.getString("vertexType"), "Observable");
		assertTrue(((Collection)dnsRecord.get("description")).contains("Requested domain name DALE-PC.ORNL.GOV resolved to IP address 89.79.77.77"));
		assertTrue(((Collection)dnsRecord.get("source")).contains("DNSRecord"));
		assertEquals(dnsRecord.getString("observableType"), "DNS Record");
		sourceDocument = dnsRecord.getString("sourceDocument");
		try {
			Observable sourceObservable = new Observable().fromXMLString(sourceDocument);
			assertTrue(sourceObservable.validate());
		} catch (SAXException e) {
			e.printStackTrace();
		}

		System.out.println("Testing DNS Record -> Domain Name ... ");
		String dnsRecordID = getVertIDByName("DALE-PC.ORNL.GOV_resolved_to_89.79.77.77", vertices);
		String dnsNameID = getVertIDByName("DALE-PC.ORNL.GOV", vertices);
		JSONObject expectedEdge = getEdgeByProps(dnsRecordID, dnsNameID, "Sub-Observable", edges);
		assertNotNull(expectedEdge); 

		System.out.println("Testing DNS Record -> Requested IP ... ");
		dnsRecordID = getVertIDByName("DALE-PC.ORNL.GOV_resolved_to_89.79.77.77", vertices);
		String reqIpID = getVertIDByName("89.79.77.77", vertices);
		expectedEdge = getEdgeByProps(dnsRecordID, reqIpID, "Sub-Observable", edges);
		assertNotNull(expectedEdge);

		System.out.println("Testing DNS Record -> Source IP ... ");
		dnsRecordID = getVertIDByName("DALE-PC.ORNL.GOV_resolved_to_89.79.77.77", vertices);
		String srcIpID = getVertIDByName("128.219.177.244", vertices);
		expectedEdge = getEdgeByProps(dnsRecordID, srcIpID, "Sub-Observable", edges);
		assertNotNull(expectedEdge);

		System.out.println("Testing DNS Record -> Destination IP ... ");
		dnsRecordID = getVertIDByName("DALE-PC.ORNL.GOV_resolved_to_89.79.77.77", vertices);
		String dstIpID = getVertIDByName("68.87.73.245", vertices);
		expectedEdge = getEdgeByProps(dnsRecordID, dstIpID, "Sub-Observable", edges);
		assertNotNull(expectedEdge);
	}
}