package gov.ornl.stucco.graph_extractors;

import org.mitre.cybox.cybox_2.Observable;

import org.xml.sax.SAXException;

import org.junit.Test;

import static org.junit.Assert.*;

import org.json.JSONObject;
import org.json.JSONArray;


/**
 * Unit test for Argus Extractor. 
 */
public class ArgusGraphExtractorTest	{ 	
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
	public void test_empty_document()	{

		System.out.println();
		System.out.println("STIXExtractor.ArgusExtractorTest.test_empty_document()");

		String[] headers = "StartTime,Flgs,Proto,SrcAddr,Sport,Dir,DstAddr,Dport,TotPkts,TotBytes,State".split(",");
		String argusInfo = "";

		ArgusGraphExtractor argusExtractor = new ArgusGraphExtractor(headers, argusInfo);
		JSONObject graph = argusExtractor.getGraph();
		
		System.out.println("Testing that graph is null");
		assertNull(graph);
	}

  /**
	 * Test one element
	 */
	@Test
	public void test_one_element_with_header_to_graph()	throws SAXException {
		System.out.println();
		System.out.println("STIXExtractor.ArgusExtractorTest.test_one_element_with_header()");

		String[] headers = "StartTime,Flgs,Proto,SrcAddr,Sport,Dir,DstAddr,Dport,TotPkts,TotBytes,State".split(",");
		String argusInfo = "1373553586.136399, e s,6,10.10.10.1,56867,->,10.10.10.100,22,8,585,";
		
		ArgusGraphExtractor argusExtractor = new ArgusGraphExtractor(headers, argusInfo);

		String expectedGraphString = 
		"{ " +
		"  \"vertices\": { " +
		"    \"stucco:port-91231ac0-af1d-42a8-aa2f-b40facb3672b\": { " +
		"      \"sourceDocument\": \"<cybox:Observable xmlns:cybox=\\\"http://cybox.mitre.org/cybox-2\\\" xmlns:stucco=\\\"gov.ornl.stucco\\\" id=\\\"stucco:port-91231ac0-af1d-42a8-aa2f-b40facb3672b\\\"><cybox:Title>Port<cybox:Title><cybox:Observable_Source><cyboxCommon:Information_Source_Type xmlns:cyboxCommon=\\\"http://cybox.mitre.org/common-2\\\">Argus<cyboxCommon:Information_Source_Type><cybox:Observable_Source><cybox:Object id=\\\"stucco:port-56867\\\"><cybox:Description>56867<cybox:Description><cybox:Properties xmlns:PortObj=\\\"http://cybox.mitre.org/objects#PortObject-2\\\" xmlns:xsi=\\\"http://www.w3.org/2001/XMLSchema-instance\\\" xsi:type=\\\"PortObj:PortObjectType\\\"><PortObj:Port_Value>56867<PortObj:Port_Value><cybox:Properties><cybox:Object><cybox:Observable>\", " +
		"      \"vertexType\": \"Observable\", " +
		"      \"name\": \"56867\", " +
		"      \"description\": [\"56867\"], " +
		"      \"source\": [\"Argus\"], " +
		"      \"observableType\": \"Port\" " +
		"    }, " +
		"    \"stucco:flow-f3059b51-dadf-4b24-bf34-6a4312619209\": { " +
		"      \"sourceDocument\": \"<cybox:Observable xmlns:cybox=\\\"http://cybox.mitre.org/cybox-2\\\" xmlns:stucco=\\\"gov.ornl.stucco\\\" id=\\\"stucco:flow-f3059b51-dadf-4b24-bf34-6a4312619209\\\"><cybox:Title>Flow<cybox:Title><cybox:Observable_Source><cyboxCommon:Information_Source_Type xmlns:cyboxCommon=\\\"http://cybox.mitre.org/common-2\\\">Argus<cyboxCommon:Information_Source_Type><cybox:Observable_Source><cybox:Object id=\\\"stucco:flow-168430081_56867-168430180_22\\\"><cybox:Description>10.10.10.1, port 56867 to 10.10.10.100, port 22<cybox:Description><cybox:Properties xmlns:NetFlowObj=\\\"http://cybox.mitre.org/objects#NetworkFlowObject-2\\\" xmlns:xsi=\\\"http://www.w3.org/2001/XMLSchema-instance\\\" xsi:type=\\\"NetFlowObj:NetworkFlowObjectType\\\"><cyboxCommon:Custom_Properties xmlns:cyboxCommon=\\\"http://cybox.mitre.org/common-2\\\"><cyboxCommon:Property name=\\\"TotBytes\\\">585<cyboxCommon:Property><cyboxCommon:Property name=\\\"Flgs\\\"> e s<cyboxCommon:Property><cyboxCommon:Property name=\\\"State\\\">REQ<cyboxCommon:Property><cyboxCommon:Property name=\\\"StartTime\\\">1373553586.136399<cyboxCommon:Property><cyboxCommon:Property name=\\\"Dir\\\">-&gt;<cyboxCommon:Property><cyboxCommon:Property name=\\\"TotPkts\\\">8<cyboxCommon:Property><cyboxCommon:Custom_Properties><NetFlowObj:Network_Flow_Label><NetFlowObj:Src_Socket_Address object_reference=\\\"stucco:address-4def804c-8d8f-46cc-b019-39232f67c8a1\\\" /><NetFlowObj:Dest_Socket_Address object_reference=\\\"stucco:address-27fc0f6a-311b-40aa-87ba-4194985af525\\\" /><NetFlowObj:IP_Protocol>6<NetFlowObj:IP_Protocol><NetFlowObj:Network_Flow_Label><cybox:Properties><cybox:Object><cybox:Observable>\", " +
		"      \"vertexType\": \"Observable\", " +
		"      \"name\": \"10.10.10.1:56867_through_10.10.10.100:22\", " +
		"      \"description\": [\"10.10.10.1, port 56867 to 10.10.10.100, port 22\"], " +
		"      \"source\": [\"Argus\"], " +
		"      \"observableType\": \"Network Flow\" " +
		"    }, " +
		"    \"stucco:ip-291d7bdb-761c-48e8-892a-aa279d7d53cf\": { " +
		"      \"sourceDocument\": \"<cybox:Observable xmlns:cybox=\\\"http://cybox.mitre.org/cybox-2\\\" xmlns:stucco=\\\"gov.ornl.stucco\\\" id=\\\"stucco:ip-291d7bdb-761c-48e8-892a-aa279d7d53cf\\\"><cybox:Title>IP<cybox:Title><cybox:Observable_Source><cyboxCommon:Information_Source_Type xmlns:cyboxCommon=\\\"http://cybox.mitre.org/common-2\\\">Argus<cyboxCommon:Information_Source_Type><cybox:Observable_Source><cybox:Object id=\\\"stucco:ip-168430180\\\"><cybox:Description>10.10.10.100<cybox:Description><cybox:Properties xmlns:AddressObj=\\\"http://cybox.mitre.org/objects#AddressObject-2\\\" xmlns:xsi=\\\"http://www.w3.org/2001/XMLSchema-instance\\\" category=\\\"ipv4-addr\\\" xsi:type=\\\"AddressObj:AddressObjectType\\\"><AddressObj:Address_Value>10.10.10.100<AddressObj:Address_Value><cybox:Properties><cybox:Object><cybox:Observable>\", " +
		"      \"vertexType\": \"IP\", " +
		"      \"ipInt\": 168430180, " +
		"      \"name\": \"10.10.10.100\", " +
		"      \"description\": [\"10.10.10.100\"], " +
		"      \"source\": [\"Argus\"], " +
		"      \"observableType\": \"Address\" " +
		"    }, " +
		"    \"stucco:port-7d05116d-33c4-4020-800e-77bd1ed327c7\": { " +
		"      \"sourceDocument\": \"<cybox:Observable xmlns:cybox=\\\"http://cybox.mitre.org/cybox-2\\\" xmlns:stucco=\\\"gov.ornl.stucco\\\" id=\\\"stucco:port-7d05116d-33c4-4020-800e-77bd1ed327c7\\\"><cybox:Title>Port<cybox:Title><cybox:Observable_Source><cyboxCommon:Information_Source_Type xmlns:cyboxCommon=\\\"http://cybox.mitre.org/common-2\\\">Argus<cyboxCommon:Information_Source_Type><cybox:Observable_Source><cybox:Object id=\\\"stucco:port-22\\\"><cybox:Description>22<cybox:Description><cybox:Properties xmlns:PortObj=\\\"http://cybox.mitre.org/objects#PortObject-2\\\" xmlns:xsi=\\\"http://www.w3.org/2001/XMLSchema-instance\\\" xsi:type=\\\"PortObj:PortObjectType\\\"><PortObj:Port_Value>22<PortObj:Port_Value><cybox:Properties><cybox:Object><cybox:Observable>\", " +
		"      \"vertexType\": \"Observable\", " +
		"      \"name\": \"22\", " +
		"      \"description\": [\"22\"], " +
		"      \"source\": [\"Argus\"], " +
		"      \"observableType\": \"Port\" " +
		"    }, " +
		"    \"stucco:address-4def804c-8d8f-46cc-b019-39232f67c8a1\": { " +
		"      \"sourceDocument\": \"<cybox:Observable xmlns:cybox=\\\"http://cybox.mitre.org/cybox-2\\\" xmlns:stucco=\\\"gov.ornl.stucco\\\" id=\\\"stucco:address-4def804c-8d8f-46cc-b019-39232f67c8a1\\\"><cybox:Title>Address<cybox:Title><cybox:Observable_Source><cyboxCommon:Information_Source_Type xmlns:cyboxCommon=\\\"http://cybox.mitre.org/common-2\\\">Argus<cyboxCommon:Information_Source_Type><cybox:Observable_Source><cybox:Object id=\\\"stucco:address-168430081_56867\\\"><cybox:Description>10.10.10.1, port 56867<cybox:Description><cybox:Properties xmlns:SocketAddressObj=\\\"http://cybox.mitre.org/objects#SocketAddressObject-1\\\" xmlns:xsi=\\\"http://www.w3.org/2001/XMLSchema-instance\\\" xsi:type=\\\"SocketAddressObj:SocketAddressObjectType\\\"><SocketAddressObj:IP_Address object_reference=\\\"stucco:ip-eb0b10ae-9b52-40cb-99be-a327710a933d\\\" /><SocketAddressObj:Port object_reference=\\\"stucco:port-91231ac0-af1d-42a8-aa2f-b40facb3672b\\\" /><cybox:Properties><cybox:Object><cybox:Observable>\", " +
		"      \"vertexType\": \"Observable\", " +
		"      \"name\": \"10.10.10.1:56867\", " +
		"      \"description\": [\"10.10.10.1, port 56867\"], " +
		"      \"source\": [\"Argus\"], " +
		"      \"observableType\": \"Socket Address\" " +
		"    }, " +
		"    \"stucco:ip-eb0b10ae-9b52-40cb-99be-a327710a933d\": { " +
		"      \"sourceDocument\": \"<cybox:Observable xmlns:cybox=\\\"http://cybox.mitre.org/cybox-2\\\" xmlns:stucco=\\\"gov.ornl.stucco\\\" id=\\\"stucco:ip-eb0b10ae-9b52-40cb-99be-a327710a933d\\\"><cybox:Title>IP<cybox:Title><cybox:Observable_Source><cyboxCommon:Information_Source_Type xmlns:cyboxCommon=\\\"http://cybox.mitre.org/common-2\\\">Argus<cyboxCommon:Information_Source_Type><cybox:Observable_Source><cybox:Object id=\\\"stucco:ip-168430081\\\"><cybox:Description>10.10.10.1<cybox:Description><cybox:Properties xmlns:AddressObj=\\\"http://cybox.mitre.org/objects#AddressObject-2\\\" xmlns:xsi=\\\"http://www.w3.org/2001/XMLSchema-instance\\\" category=\\\"ipv4-addr\\\" xsi:type=\\\"AddressObj:AddressObjectType\\\"><AddressObj:Address_Value>10.10.10.1<AddressObj:Address_Value><cybox:Properties><cybox:Object><cybox:Observable>\", " +
		"      \"vertexType\": \"IP\", " +
		"      \"ipInt\": 168430081, " +
		"      \"name\": \"10.10.10.1\", " +
		"      \"description\": [\"10.10.10.1\"], " +
		"      \"source\": [\"Argus\"], " +
		"      \"observableType\": \"Address\" " +
		"    }, " +
		"    \"stucco:address-27fc0f6a-311b-40aa-87ba-4194985af525\": { " +
		"      \"sourceDocument\": \"<cybox:Observable xmlns:cybox=\\\"http://cybox.mitre.org/cybox-2\\\" xmlns:stucco=\\\"gov.ornl.stucco\\\" id=\\\"stucco:address-27fc0f6a-311b-40aa-87ba-4194985af525\\\"><cybox:Title>Address<cybox:Title><cybox:Observable_Source><cyboxCommon:Information_Source_Type xmlns:cyboxCommon=\\\"http://cybox.mitre.org/common-2\\\">Argus<cyboxCommon:Information_Source_Type><cybox:Observable_Source><cybox:Object id=\\\"stucco:address-168430180_22\\\"><cybox:Description>10.10.10.100, port 22<cybox:Description><cybox:Properties xmlns:SocketAddressObj=\\\"http://cybox.mitre.org/objects#SocketAddressObject-1\\\" xmlns:xsi=\\\"http://www.w3.org/2001/XMLSchema-instance\\\" xsi:type=\\\"SocketAddressObj:SocketAddressObjectType\\\"><SocketAddressObj:IP_Address object_reference=\\\"stucco:ip-291d7bdb-761c-48e8-892a-aa279d7d53cf\\\" /><SocketAddressObj:Port object_reference=\\\"stucco:port-7d05116d-33c4-4020-800e-77bd1ed327c7\\\" /><cybox:Properties><cybox:Object><cybox:Observable>\", " +
		"      \"vertexType\": \"Observable\", " +
		"      \"name\": \"10.10.10.100:22\", " +
		"      \"description\": [\"10.10.10.100, port 22\"], " +
		"      \"source\": [\"Argus\"], " +
		"      \"observableType\": \"Socket Address\" " +
		"    } " +
		"  }, " +
		"  \"edges\": [ " +
		"    { " +
		"      \"outVertID\": \"stucco:flow-f3059b51-dadf-4b24-bf34-6a4312619209\", " +
		"      \"inVertID\": \"stucco:address-4def804c-8d8f-46cc-b019-39232f67c8a1\", " +
		"      \"relation\": \"Sub-Observable\" " +
		"    }, " +
		"    { " +
		"      \"outVertID\": \"stucco:flow-f3059b51-dadf-4b24-bf34-6a4312619209\", " +
		"      \"inVertID\": \"stucco:address-27fc0f6a-311b-40aa-87ba-4194985af525\", " +
		"      \"relation\": \"Sub-Observable\" " +
		"    }, " +
		"    { " +
		"      \"outVertID\": \"stucco:address-4def804c-8d8f-46cc-b019-39232f67c8a1\", " +
		"      \"inVertID\": \"stucco:ip-eb0b10ae-9b52-40cb-99be-a327710a933d\", " +
		"      \"relation\": \"Sub-Observable\" " +
		"    }, " +
		"    { " +
		"      \"outVertID\": \"stucco:address-4def804c-8d8f-46cc-b019-39232f67c8a1\", " +
		"      \"inVertID\": \"stucco:port-91231ac0-af1d-42a8-aa2f-b40facb3672b\", " +
		"      \"relation\": \"Sub-Observable\" " +
		"    }, " +
		"    { " +
		"      \"outVertID\": \"stucco:address-27fc0f6a-311b-40aa-87ba-4194985af525\", " +
		"      \"inVertID\": \"stucco:ip-291d7bdb-761c-48e8-892a-aa279d7d53cf\", " +
		"      \"relation\": \"Sub-Observable\" " +
		"    }, " +
		"    { " +
		"      \"outVertID\": \"stucco:address-27fc0f6a-311b-40aa-87ba-4194985af525\", " +
		"      \"inVertID\": \"stucco:port-7d05116d-33c4-4020-800e-77bd1ed327c7\", " +
		"      \"relation\": \"Sub-Observable\" " +
		"    } " +
		"  ] " +
		"}";

		JSONObject expectedGraph = new JSONObject(expectedGraphString);
		JSONObject receivedGraph = argusExtractor.getGraph();

		JSONObject expectedVertices = expectedGraph.getJSONObject("vertices");
		JSONObject receivedVertices = receivedGraph.getJSONObject("vertices");
		
		System.out.println("Testing IP ... ");
		JSONObject receivedIP = getVertByName("10.10.10.1", receivedVertices);
		JSONObject expectedIP = expectedVertices.getJSONObject("stucco:address-27fc0f6a-311b-40aa-87ba-4194985af525");
		boolean equals = compareVertProperties(receivedIP, expectedIP);
		assertTrue(equals);
		String sourceDocument = receivedIP.getString("sourceDocument");
		Observable sourceObservable = new Observable().fromXMLString(sourceDocument);
		assertTrue(sourceObservable.validate());

		System.out.println("Testing IP ... ");
		receivedIP = getVertByName("10.10.10.100", receivedVertices);
		expectedIP = expectedVertices.getJSONObject("stucco:ip-291d7bdb-761c-48e8-892a-aa279d7d53cf");
		equals = compareVertProperties(receivedIP, expectedIP);
		assertTrue(equals);
		sourceDocument = receivedIP.getString("sourceDocument");
		sourceObservable = new Observable().fromXMLString(sourceDocument);
		assertTrue(sourceObservable.validate());

		System.out.println("Testing Port ... ");
		receivedIP = getVertByName("22", receivedVertices);
		expectedIP = expectedVertices.getJSONObject("stucco:port-7d05116d-33c4-4020-800e-77bd1ed327c7");
		equals = compareVertProperties(receivedIP, expectedIP);
		assertTrue(equals);
		sourceDocument = receivedIP.getString("sourceDocument");
		sourceObservable = new Observable().fromXMLString(sourceDocument);
		assertTrue(sourceObservable.validate());

		System.out.println("Testing Port ... ");
		receivedIP = getVertByName("56867", receivedVertices);
		expectedIP = expectedVertices.getJSONObject("stucco:port-91231ac0-af1d-42a8-aa2f-b40facb3672b");
		equals = compareVertProperties(receivedIP, expectedIP);
		assertTrue(equals);
		sourceDocument = receivedIP.getString("sourceDocument");
		sourceObservable = new Observable().fromXMLString(sourceDocument);
		assertTrue(sourceObservable.validate());

		System.out.println("Testing Address ... ");
		receivedIP = getVertByName("10.10.10.1:56867", receivedVertices);
		expectedIP = expectedVertices.getJSONObject("stucco:address-4def804c-8d8f-46cc-b019-39232f67c8a1");
		equals = compareVertProperties(receivedIP, expectedIP);
		assertTrue(equals);
		sourceDocument = receivedIP.getString("sourceDocument");
		sourceObservable = new Observable().fromXMLString(sourceDocument);
		assertTrue(sourceObservable.validate());

		System.out.println("Testing Address ... ");
		receivedIP = getVertByName("10.10.10.100:22", receivedVertices);
		expectedIP = expectedVertices.getJSONObject("stucco:address-27fc0f6a-311b-40aa-87ba-4194985af525");
		equals = compareVertProperties(receivedIP, expectedIP);
		assertTrue(equals);
		sourceDocument = receivedIP.getString("sourceDocument");
		sourceObservable = new Observable().fromXMLString(sourceDocument);
		assertTrue(sourceObservable.validate());

		System.out.println("Testing Network Flow ... ");
		receivedIP = getVertByName("10.10.10.1:56867_through_10.10.10.100:22", receivedVertices);
		expectedIP = expectedVertices.getJSONObject("stucco:flow-f3059b51-dadf-4b24-bf34-6a4312619209");
		equals = compareVertProperties(receivedIP, expectedIP);
		assertTrue(equals);
		sourceDocument = receivedIP.getString("sourceDocument");
		sourceObservable = new Observable().fromXMLString(sourceDocument);
		assertTrue(sourceObservable.validate());

		JSONArray expectedEdges = expectedGraph.getJSONArray("edges");
		JSONArray receivedEdges = receivedGraph.getJSONArray("edges");

		System.out.println("Testing Address -> IP ... ");
		String addressID = getVertIDByName("10.10.10.1:56867", receivedVertices);
		String ipID = getVertIDByName("10.10.10.1", receivedVertices);
		JSONObject expectedEdge = getEdgeByProps(addressID, ipID, "Sub-Observable", receivedEdges);
		assertNotNull(expectedEdge); 

		System.out.println("Testing Address -> Port ... ");
		addressID = getVertIDByName("10.10.10.1:56867", receivedVertices);
		String portID = getVertIDByName("56867", receivedVertices);
		expectedEdge = getEdgeByProps(addressID, portID, "Sub-Observable", receivedEdges);
		assertNotNull(expectedEdge);

		System.out.println("Testing Address -> IP ... ");
		addressID = getVertIDByName("10.10.10.100:22", receivedVertices);
		ipID = getVertIDByName("10.10.10.100", receivedVertices);
		expectedEdge = getEdgeByProps(addressID, ipID, "Sub-Observable", receivedEdges);
		assertNotNull(expectedEdge); 

		System.out.println("Testing Address -> Port ... ");
		addressID = getVertIDByName("10.10.10.100:22", receivedVertices);
		portID = getVertIDByName("22", receivedVertices);
		expectedEdge = getEdgeByProps(addressID, portID, "Sub-Observable", receivedEdges);
		assertNotNull(expectedEdge);

		System.out.println("Testing Network Flow -> Address ... ");
		String flowID = getVertIDByName("10.10.10.1:56867_through_10.10.10.100:22", receivedVertices);
		addressID = getVertIDByName("10.10.10.1:56867", receivedVertices);
		expectedEdge = getEdgeByProps(flowID, addressID, "Sub-Observable", receivedEdges);
		assertNotNull(expectedEdge);

		System.out.println("Testing Network Flow -> Address ... ");
		flowID = getVertIDByName("10.10.10.1:56867_through_10.10.10.100:22", receivedVertices);
		addressID = getVertIDByName("10.10.10.100:22", receivedVertices);
		expectedEdge = getEdgeByProps(flowID, addressID, "Sub-Observable", receivedEdges);
		assertNotNull(expectedEdge);
	}
}