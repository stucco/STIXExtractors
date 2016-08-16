package STIXExtractor;

import java.util.List;
import java.util.Map;
import java.util.HashMap;

import java.io.IOException;

import org.apache.commons.csv.CSVRecord;

import org.mitre.stix.stix_1.STIXPackage;
import org.mitre.cybox.cybox_2.Observable;

import org.xml.sax.SAXException;

import org.junit.Test;

import org.json.JSONObject;
import org.json.JSONArray;

import static org.junit.Assert.*;

import STIXExtractor.HTTPDataGraphExtractor;

/**
 * Unit test for HTTPDataExtractor.
 */
public class HTTPDataGraphExtractorTest extends STIXExtractor {
	
	/**
	 * Test empty document
	 */
	//@Test
	public void test_empty_doc() {
			 
		System.out.println();
		System.out.println("STIXExtractor.HTTPDataExtractorTest.test_empty_doc()");

		String httpInfo = "";

		HTTPDataGraphExtractor httpGraphExtractor = new HTTPDataGraphExtractor(httpInfo);
		JSONObject receivedGraph = httpGraphExtractor.getGraph();

		System.out.println("Testing that Graph is null");
		assertTrue(receivedGraph == null);
	}

	/**
	 * Test empty element
	 */
	@Test
	public void test_empty_element() {
			
		System.out.println();
		System.out.println("STIXExtractor.HTTPDataExtractorTest.test_empty_element()");

		String httpInfo = 
			"filename,recnum,file_type,amp_version,site,saddr,daddr,request_len,dport,times_seen,first_seen_timet," +
 			"last_seen_timet,method,request,query_terms,accept_language,user_agent,server_fqdn,referer,uri,clean_data," +
 			"full_data,scountrycode,sorganization,slat,slong,dcountrycode,dorganization,dlat,dlong,distance\n" +
			",,,,,,,,,,,,,,,,,,,,,,,,,,,,,,";

		HTTPDataGraphExtractor httpGraphExtractor = new HTTPDataGraphExtractor(httpInfo);
		JSONObject receivedGraph = httpGraphExtractor.getGraph();

		System.out.println("Testing that Graph is null");
		assertTrue(receivedGraph == null);
	}

	/**
	 * Test element with just header
	 */
	@Test
	public void test_element_with_header() {
			
		System.out.println();
		System.out.println("STIXExtractor.HTTPDataExtractorTest.test_element_with_header()");

		String httpInfo = 
			"filename,recnum,file_type,amp_version,site,saddr,daddr,request_len,dport,times_seen,first_seen_timet," +
 			"last_seen_timet,method,request,query_terms,accept_language,user_agent,server_fqdn,referer,uri,clean_data," +
 			"full_data,scountrycode,sorganization,slat,slong,dcountrycode,dorganization,dlat,dlong,distance";
		
		HTTPDataGraphExtractor httpGraphExtractor = new HTTPDataGraphExtractor(httpInfo);
		JSONObject receivedGraph = httpGraphExtractor.getGraph();

		System.out.println("Testing that Graph is null");
		assertTrue(receivedGraph == null);
	}

	/**
	 * Test one element
	 */
	@Test
	public void test_one_element_with_header() throws SAXException {
			
		System.out.println();
		System.out.println("STIXExtractor.HTTPDataExtractorTest.test_one_element_with_header()");

		String httpInfo = 
			"filename,recnum,file_type,amp_version,site,saddr,daddr,request_len,dport,times_seen,first_seen_timet," +
 			"last_seen_timet,method,request,query_terms,accept_language,user_agent,server_fqdn,referer,uri,clean_data," +
 			"full_data,scountrycode,sorganization,slat,slong,dcountrycode,dorganization,dlat,dlong,distance \n" +
			"20150909000417-ornl-ampHttpR4-1,5763,1,2,ornl,128.219.49.13,54.192.138.232,846,80,1,2015-09-09 00:03:09+00,2015-09-09 00:03:09+00," +
			"GET,/tv2n/vpaid/8bc5b7b,[],\"en-US,en;q=0.8\",\"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36\"," +
			"cdn455.telemetryverification.net,http://portal.tds.net/?inc=4,User-Agent Accept-Language Referer Host,HTTP/1.1,GET /tv2n/vpaid/8bc5b7b,US,oak ridge national laboratory," +	
			"36.02103,-84.25273,US,amazon.com inc.,34.0634,-118.2393,1917.613986";

		HTTPDataGraphExtractor httpGraphExtractor = new HTTPDataGraphExtractor(httpInfo);

		String expectedString = 
		"{ " +
		"  \"vertices\": { " +
		"    \"stucco:port-2af747eb-7149-4130-b280-d3e506e1c747\": { " +
		"      \"sourceDocument\": \"<cybox:Observable xmlns:cybox=\\\"http://cybox.mitre.org/cybox-2\\\" xmlns:stucco=\\\"gov.ornl.stucco\\\" id=\\\"stucco:port-2af747eb-7149-4130-b280-d3e506e1c747\\\"><cybox:Title>Port</cybox:Title><cybox:Observable_Source><cyboxCommon:Information_Source_Type xmlns:cyboxCommon=\\\"http://cybox.mitre.org/common-2\\\">HTTPRequest</cyboxCommon:Information_Source_Type></cybox:Observable_Source><cybox:Object id=\\\"stucco:port-80\\\"><cybox:Description>80</cybox:Description><cybox:Properties xmlns:PortObj=\\\"http://cybox.mitre.org/objects#PortObject-2\\\" xmlns:xsi=\\\"http://www.w3.org/2001/XMLSchema-instance\\\" xsi:type=\\\"PortObj:PortObjectType\\\"><PortObj:Port_Value>80</PortObj:Port_Value></cybox:Properties></cybox:Object></cybox:Observable>\", " +
		"      \"vertexType\": \"Observable\", " +
		"      \"name\": \"80\", " +
		"      \"description\": [\"80\"], " +
		"      \"source\": [\"HTTPRequest\"], " +
		"      \"observableType\": \"Port\" " +
		"    }, " +
		"    \"stucco:httpRequest-70114697-9ea6-4bd3-a0ff-4f578df1313b\": { " +
		"      \"sourceDocument\": \"<cybox:Observable xmlns:cybox=\\\"http://cybox.mitre.org/cybox-2\\\" xmlns:stucco=\\\"gov.ornl.stucco\\\" id=\\\"stucco:httpRequest-70114697-9ea6-4bd3-a0ff-4f578df1313b\\\"><cybox:Title>HTTPRequest</cybox:Title><cybox:Observable_Source><cyboxCommon:Information_Source_Type xmlns:cyboxCommon=\\\"http://cybox.mitre.org/common-2\\\">HTTPRequest</cyboxCommon:Information_Source_Type></cybox:Observable_Source><cybox:Object><cybox:Description>HTTP request of URL /tv2n/vpaid/8bc5b7b</cybox:Description><cybox:Properties xmlns:HTTPSessionObj=\\\"http://cybox.mitre.org/objects#HTTPSessionObject-2\\\" xmlns:xsi=\\\"http://www.w3.org/2001/XMLSchema-instance\\\" xsi:type=\\\"HTTPSessionObj:HTTPSessionObjectType\\\"><HTTPSessionObj:HTTP_Request_Response><HTTPSessionObj:HTTP_Client_Request><HTTPSessionObj:HTTP_Request_Line><HTTPSessionObj:HTTP_Method>GET</HTTPSessionObj:HTTP_Method><HTTPSessionObj:Value>/tv2n/vpaid/8bc5b7b</HTTPSessionObj:Value><HTTPSessionObj:Version>2</HTTPSessionObj:Version></HTTPSessionObj:HTTP_Request_Line><HTTPSessionObj:HTTP_Request_Header><HTTPSessionObj:Raw_Header>GET /tv2n/vpaid/8bc5b7b</HTTPSessionObj:Raw_Header><HTTPSessionObj:Parsed_Header><HTTPSessionObj:Accept_Language>en-US,en;q=0.8</HTTPSessionObj:Accept_Language><HTTPSessionObj:Content_Length>846</HTTPSessionObj:Content_Length><HTTPSessionObj:Date>2015-09-09 00:03:09+00</HTTPSessionObj:Date><HTTPSessionObj:From object_reference=\\\"stucco:ip-b74773cb-18df-4b4c-9415-8cd30cf54b21\\\" /><HTTPSessionObj:Host><HTTPSessionObj:Domain_Name object_reference=\\\"stucco:dnsName-fbb9059c-c267-4b18-8b1d-9113638c99e7\\\" /><HTTPSessionObj:Port object_reference=\\\"stucco:port-2af747eb-7149-4130-b280-d3e506e1c747\\\" /></HTTPSessionObj:Host><HTTPSessionObj:Referer object_reference=\\\"stucco:Observable-306731ac-f1a3-4ca4-988b-c5e65016d238\\\" /><HTTPSessionObj:User_Agent>Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36</HTTPSessionObj:User_Agent></HTTPSessionObj:Parsed_Header></HTTPSessionObj:HTTP_Request_Header></HTTPSessionObj:HTTP_Client_Request></HTTPSessionObj:HTTP_Request_Response></cybox:Properties></cybox:Object></cybox:Observable>\", " +
		"      \"vertexType\": \"Observable\", " +
		"      \"name\": \"/tv2n/vpaid/8bc5b7b\", " +
		"      \"description\": [\"HTTP request of URL /tv2n/vpaid/8bc5b7b\"], " +
		"      \"source\": [\"HTTPRequest\"], " +
		"      \"observableType\": \"HTTP Session\" " +
		"    }, " +
		"    \"stucco:Observable-306731ac-f1a3-4ca4-988b-c5e65016d238\": { " +
		"      \"sourceDocument\": \"<cybox:Observable xmlns:cybox=\\\"http://cybox.mitre.org/cybox-2\\\" xmlns:stucco=\\\"gov.ornl.stucco\\\" id=\\\"stucco:Observable-306731ac-f1a3-4ca4-988b-c5e65016d238\\\"><cybox:Object><cybox:Properties xmlns:URIObj=\\\"http://cybox.mitre.org/objects#URIObject-2\\\" xmlns:xsi=\\\"http://www.w3.org/2001/XMLSchema-instance\\\" xsi:type=\\\"URIObj:URIObjectType\\\"><URIObj:Value>http://portal.tds.net/?inc=4</URIObj:Value></cybox:Properties></cybox:Object></cybox:Observable>\", " +
		"      \"vertexType\": \"Observable\", " +
		"      \"name\": \"http://portal.tds.net/?inc=4\", " +
		"      \"observableType\": \"URI\" " +
		"    }, " +
		"    \"stucco:dnsName-fbb9059c-c267-4b18-8b1d-9113638c99e7\": { " +
		"      \"sourceDocument\": \"<cybox:Observable xmlns:cybox=\\\"http://cybox.mitre.org/cybox-2\\\" xmlns:stucco=\\\"gov.ornl.stucco\\\" id=\\\"stucco:dnsName-fbb9059c-c267-4b18-8b1d-9113638c99e7\\\"><cybox:Title>DNSName</cybox:Title><cybox:Observable_Source><cyboxCommon:Information_Source_Type xmlns:cyboxCommon=\\\"http://cybox.mitre.org/common-2\\\">HTTPRequest</cyboxCommon:Information_Source_Type></cybox:Observable_Source><cybox:Object id=\\\"stucco:dnsName-cdn455.telemetryverification.net\\\"><cybox:Description>cdn455.telemetryverification.net</cybox:Description><cybox:Properties xmlns:DomainNameObj=\\\"http://cybox.mitre.org/objects#DomainNameObject-1\\\" xmlns:xsi=\\\"http://www.w3.org/2001/XMLSchema-instance\\\" xsi:type=\\\"DomainNameObj:DomainNameObjectType\\\"><DomainNameObj:Value>cdn455.telemetryverification.net</DomainNameObj:Value></cybox:Properties><cybox:Related_Objects><cybox:Related_Object idref=\\\"stucco:ip-3ce3d292-07db-4fb6-ad4e-a012415a8bef\\\"><cybox:Relationship>Resolved_To</cybox:Relationship></cybox:Related_Object></cybox:Related_Objects></cybox:Object></cybox:Observable>\", " +
		"      \"vertexType\": \"Observable\", " +
		"      \"name\": \"cdn455.telemetryverification.net\", " +
		"      \"description\": [\"cdn455.telemetryverification.net\"], " +
		"      \"source\": [\"HTTPRequest\"], " +
		"      \"observableType\": \"Domain Name\" " +
		"    }, " +
		"    \"stucco:ip-b74773cb-18df-4b4c-9415-8cd30cf54b21\": { " +
		"      \"sourceDocument\": \"<cybox:Observable xmlns:cybox=\\\"http://cybox.mitre.org/cybox-2\\\" xmlns:stucco=\\\"gov.ornl.stucco\\\" id=\\\"stucco:ip-b74773cb-18df-4b4c-9415-8cd30cf54b21\\\"><cybox:Title>IP</cybox:Title><cybox:Observable_Source><cyboxCommon:Information_Source_Type xmlns:cyboxCommon=\\\"http://cybox.mitre.org/common-2\\\">HTTPRequest</cyboxCommon:Information_Source_Type></cybox:Observable_Source><cybox:Object id=\\\"stucco:ip-2161848589\\\"><cybox:Description>128.219.49.13</cybox:Description><cybox:Properties xmlns:AddressObj=\\\"http://cybox.mitre.org/objects#AddressObject-2\\\" xmlns:xsi=\\\"http://www.w3.org/2001/XMLSchema-instance\\\" category=\\\"ipv4-addr\\\" xsi:type=\\\"AddressObj:AddressObjectType\\\"><AddressObj:Address_Value>128.219.49.13</AddressObj:Address_Value></cybox:Properties></cybox:Object></cybox:Observable>\", " +
		"      \"vertexType\": \"IP\", " +
		"      \"ipInt\": 2161848589, " +
		"      \"name\": \"128.219.49.13\", " +
		"      \"description\": [\"128.219.49.13\"], " +
		"      \"source\": [\"HTTPRequest\"], " +
		"      \"observableType\": \"Address\" " +
		"    }, " +
		"    \"stucco:ip-3ce3d292-07db-4fb6-ad4e-a012415a8bef\": { " +
		"      \"sourceDocument\": \"<cybox:Observable xmlns:cybox=\\\"http://cybox.mitre.org/cybox-2\\\" xmlns:stucco=\\\"gov.ornl.stucco\\\" id=\\\"stucco:ip-3ce3d292-07db-4fb6-ad4e-a012415a8bef\\\"><cybox:Title>IP</cybox:Title><cybox:Observable_Source><cyboxCommon:Information_Source_Type xmlns:cyboxCommon=\\\"http://cybox.mitre.org/common-2\\\">HTTPRequest</cyboxCommon:Information_Source_Type></cybox:Observable_Source><cybox:Object id=\\\"stucco:ip-918588136\\\"><cybox:Description>54.192.138.232</cybox:Description><cybox:Properties xmlns:AddressObj=\\\"http://cybox.mitre.org/objects#AddressObject-2\\\" xmlns:xsi=\\\"http://www.w3.org/2001/XMLSchema-instance\\\" category=\\\"ipv4-addr\\\" xsi:type=\\\"AddressObj:AddressObjectType\\\"><AddressObj:Address_Value>54.192.138.232</AddressObj:Address_Value></cybox:Properties></cybox:Object></cybox:Observable>\", " +
		"      \"vertexType\": \"IP\", " +
		"      \"ipInt\": 918588136, " +
		"      \"name\": \"54.192.138.232\", " +
		"      \"description\": [\"54.192.138.232\"], " +
		"      \"source\": [\"HTTPRequest\"], " +
		"      \"observableType\": \"Address\" " +
		"    } " +
		"  }, " +
		"  \"edges\": [ " +
		"    { " +
		"      \"outVertID\": \"stucco:httpRequest-70114697-9ea6-4bd3-a0ff-4f578df1313b\", " +
		"      \"inVertID\": \"stucco:ip-b74773cb-18df-4b4c-9415-8cd30cf54b21\", " +
		"      \"relation\": \"Sub-Observable\" " +
		"    }, " +
		"    { " +
		"      \"outVertID\": \"stucco:httpRequest-70114697-9ea6-4bd3-a0ff-4f578df1313b\", " +
		"      \"inVertID\": \"stucco:dnsName-fbb9059c-c267-4b18-8b1d-9113638c99e7\", " +
		"      \"relation\": \"Sub-Observable\" " +
		"    }, " +
		"    { " +
		"      \"outVertID\": \"stucco:httpRequest-70114697-9ea6-4bd3-a0ff-4f578df1313b\", " +
		"      \"inVertID\": \"stucco:port-2af747eb-7149-4130-b280-d3e506e1c747\", " +
		"      \"relation\": \"Sub-Observable\" " +
		"    }, " +
		"    { " +
		"      \"outVertID\": \"stucco:httpRequest-70114697-9ea6-4bd3-a0ff-4f578df1313b\", " +
		"      \"inVertID\": \"stucco:Observable-306731ac-f1a3-4ca4-988b-c5e65016d238\", " +
		"      \"relation\": \"Sub-Observable\" " +
		"    }, " +
		"    { " +
		"      \"outVertID\": \"stucco:dnsName-fbb9059c-c267-4b18-8b1d-9113638c99e7\", " +
		"      \"inVertID\": \"stucco:ip-3ce3d292-07db-4fb6-ad4e-a012415a8bef\", " +
		"      \"relation\": \"Sub-Observable\" " +
		"    } " +
		"  ] " +
		"}";
		JSONObject expectedGraph = new JSONObject(expectedString);
		JSONObject receivedGraph = httpGraphExtractor.getGraph();

		JSONObject expectedVertices = expectedGraph.getJSONObject("vertices");
		JSONObject receivedVertices = receivedGraph.getJSONObject("vertices");
		
		System.out.println("Testing IP ... ");
		JSONObject receivedIP = getVertByName("128.219.49.13", receivedVertices);
		JSONObject expectedIP = expectedVertices.getJSONObject("stucco:ip-b74773cb-18df-4b4c-9415-8cd30cf54b21");
		boolean equals = compareVertProperties(receivedIP, expectedIP);
		assertTrue(equals);
		String sourceDocument = receivedIP.getString("sourceDocument");
		Observable sourceObservable = new Observable().fromXMLString(sourceDocument);
		assertTrue(sourceObservable.validate());

		System.out.println("Testing IP ... ");
		receivedIP = getVertByName("54.192.138.232", receivedVertices);
		expectedIP = expectedVertices.getJSONObject("stucco:ip-3ce3d292-07db-4fb6-ad4e-a012415a8bef");
		equals = compareVertProperties(receivedIP, expectedIP);
		assertTrue(equals);
		sourceDocument = receivedIP.getString("sourceDocument");
		sourceObservable = new Observable().fromXMLString(sourceDocument);
		assertTrue(sourceObservable.validate());

		System.out.println("Testing Port ... ");
		JSONObject receivedPort = getVertByName("80", receivedVertices);
		JSONObject expectedPort = expectedVertices.getJSONObject("stucco:port-2af747eb-7149-4130-b280-d3e506e1c747");
		equals = compareVertProperties(receivedPort, expectedPort);
		assertTrue(equals);
		sourceDocument = receivedIP.getString("sourceDocument");
		sourceObservable = new Observable().fromXMLString(sourceDocument);
		assertTrue(sourceObservable.validate());

		System.out.println("Testing Domain Name ... ");
		JSONObject receivedDns = getVertByName("cdn455.telemetryverification.net", receivedVertices);
		JSONObject expectedDns = expectedVertices.getJSONObject("stucco:dnsName-fbb9059c-c267-4b18-8b1d-9113638c99e7");
		equals = compareVertProperties(receivedDns, expectedDns);
		assertTrue(equals);		
		sourceDocument = receivedIP.getString("sourceDocument");
		sourceObservable = new Observable().fromXMLString(sourceDocument);
		assertTrue(sourceObservable.validate());

		System.out.println("Testing URI ... ");
		JSONObject receivedUri = getVertByName("http://portal.tds.net/?inc=4", receivedVertices);
		JSONObject expectedUri = expectedVertices.getJSONObject("stucco:Observable-306731ac-f1a3-4ca4-988b-c5e65016d238");
		equals = compareVertProperties(receivedUri, expectedUri);
		assertTrue(equals);	
		sourceDocument = receivedIP.getString("sourceDocument");
		sourceObservable = new Observable().fromXMLString(sourceDocument);
		assertTrue(sourceObservable.validate());

		System.out.println("Testing HTTP Session ... ");
		JSONObject receivedHttp = getVertByName("/tv2n/vpaid/8bc5b7b", receivedVertices);
		JSONObject expectedHttp = expectedVertices.getJSONObject("stucco:httpRequest-70114697-9ea6-4bd3-a0ff-4f578df1313b");
		equals = compareVertProperties(receivedHttp, expectedHttp);
		assertTrue(equals);	
		sourceDocument = receivedIP.getString("sourceDocument");
		sourceObservable = new Observable().fromXMLString(sourceDocument);
		assertTrue(sourceObservable.validate());

		JSONArray expectedEdges = expectedGraph.getJSONArray("edges");
		JSONArray receivedEdges = receivedGraph.getJSONArray("edges");

		System.out.println("Testing HTTP Session -> IP ... ");
		String httpID = getVertIDByName("/tv2n/vpaid/8bc5b7b", receivedVertices);
		String addressID = getVertIDByName("128.219.49.13", receivedVertices);
		JSONObject expectedEdge = getEdgeByProps(httpID, addressID, "Sub-Observable", receivedEdges);
		assertNotNull(expectedEdge); 

		System.out.println("Testing HTTP Session -> Domain Name ... ");
		httpID = getVertIDByName("/tv2n/vpaid/8bc5b7b", receivedVertices);
		String dnsID = getVertIDByName("cdn455.telemetryverification.net", receivedVertices);
		expectedEdge = getEdgeByProps(httpID, dnsID, "Sub-Observable", receivedEdges);
		assertNotNull(expectedEdge); 

		System.out.println("Testing HTTP Session -> Port ... ");
		httpID = getVertIDByName("/tv2n/vpaid/8bc5b7b", receivedVertices);
		String portID = getVertIDByName("80", receivedVertices);
		expectedEdge = getEdgeByProps(httpID, portID, "Sub-Observable", receivedEdges);
		assertNotNull(expectedEdge); 

		System.out.println("Testing HTTP Session -> URI ... ");
		httpID = getVertIDByName("/tv2n/vpaid/8bc5b7b", receivedVertices);
		String uriID = getVertIDByName("http://portal.tds.net/?inc=4", receivedVertices);
		expectedEdge = getEdgeByProps(httpID, uriID, "Sub-Observable", receivedEdges);
		assertNotNull(expectedEdge); 

		System.out.println("Testing Domain Name -> IP ... ");
		dnsID = getVertIDByName("cdn455.telemetryverification.net", receivedVertices);
		String ipID = getVertIDByName("54.192.138.232", receivedVertices);
		expectedEdge = getEdgeByProps(dnsID, ipID, "Sub-Observable", receivedEdges);
		assertNotNull(expectedEdge); 
	}

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
}
