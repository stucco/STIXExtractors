package gov.ornl.stucco.graph_extractors;

import gov.ornl.stucco.utils.GraphUtils;
import gov.ornl.stucco.utils.ExtractorUtils;

import org.mitre.cybox.cybox_2.Observable;

import org.xml.sax.SAXException;

import org.junit.Test;

import static org.junit.Assert.*;
 
import java.io.File;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.FileNotFoundException;
import java.io.IOException;

import org.json.JSONObject;
import org.json.JSONArray;

/**
 * Unit test for Situe Extractor. 
 */
public class SituGraphExtractorTest	{
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

		SituGraphExtractor situExtractor = new SituGraphExtractor("");
		JSONObject graph = situExtractor.getGraph();

		System.out.println("Testing that graph is null");
		assertNull(graph);
	}

	/**
	 * Test one entry
	 */
	@Test
	public void test_one_entry() throws SAXException {
		String situInfo = 
			"{\"flgs\":\" e        \",\"sbytes\":950,\"dbytes\":2574,\"stime\":\"2006-10-01T18:48:19.236859\",\"dip\":\"100.1.10.101\",\"uuid\":\"abda4778-f256-520c-af09-db8addc018e3\",\"pkts\":19,\"duration\":0.049094,\"dport\":443,\"score\":5.6729677E-5,\"ltime\":\"2006-10-01T18:48:19.285953\",\"dco\":\"US\",\"contextScores\":[{\"score\":5.198947E-5,\"name\":\"Pcr\"},{\"score\":5.198947E-5,\"name\":\"Pcr_T\"},{\"score\":5.6729677E-5,\"name\":\"PrivPorts\"},{\"score\":5.6729677E-5,\"name\":\"PrivPorts_T\"}],\"dwin\":5792,\"sloc\":{\"location\":{}},\"sip\":\"89.44.100.114\",\"state\":\"FIN\",\"sco\":\"RO\",\"sload\":139324.56,\"pcr\":-0.46083996,\"direction\":\"   ->\",\"spkts\":10,\"created\":\"2016-08-17T14:35:36.392198\",\"tcprtt\":6.2E-4,\"raw\":\"tcp,FIN,0.0.0.0,2006-10-01T18:48:19.236859,2006-10-01T18:48:19.285953,0.049094,89.44.100.114,   ->,100.1.10.101,3629,443,19,3524,0,0.000000,,,,,,, e        ,1,Mws   T,0,950,10,0.000000,11584,139324.562500,0,2574,9,0.000000,5792,372835.781250,,0.000620,RO,US,,,-0.000000,\",\"dpkts\":9,\"tcpopt\":\"Mws   T\",\"dloc\":{\"location\":{}},\"sourceType\":\"argus\",\"bytes\":3524,\"srcid\":\"0.0.0.0\",\"proto\":\"tcp\",\"dload\":372835.78,\"sourceName\":\"jg\",\"sport\":3629,\"swin\":11584,\"trans\":1}";

		SituGraphExtractor situExtractor = new SituGraphExtractor(situInfo);
		JSONObject graph = situExtractor.getGraph();

		JSONObject vertices = graph.getJSONObject("vertices");
		JSONArray edges = graph.getJSONArray("edges");

		System.out.println("Testing IP ... ");
		JSONObject ipJson = getVertByName("89.44.100.114", vertices);
		assertEquals(ipJson.get("vertexType"), "IP");
		assertEquals(ipJson.get("description").toString(), "[\"89.44.100.114\"]");
		assertEquals(ipJson.get("ipInt"), ExtractorUtils.ipToLong("89.44.100.114"));
		assertEquals(ipJson.get("source").toString(), "[\"Situ\"]");
		assertEquals(ipJson.get("observableType"), "Address");
		String observableString = ipJson.getString("sourceDocument");
		Observable observable = new Observable().fromXMLString(observableString);
		assertTrue(observable.validate());

		System.out.println("Testing IP ... ");
		ipJson = getVertByName("100.1.10.101", vertices);
		assertEquals(ipJson.get("vertexType"), "IP");
		assertEquals(ipJson.get("description").toString(), "[\"100.1.10.101\"]");
		assertEquals(ipJson.get("ipInt"), ExtractorUtils.ipToLong("100.1.10.101"));
		assertEquals(ipJson.get("source").toString(), "[\"Situ\"]");
		assertEquals(ipJson.get("observableType"), "Address");
		observableString = ipJson.getString("sourceDocument");
		observable = new Observable().fromXMLString(observableString);
		assertTrue(observable.validate());

		System.out.println("Testing Port ... ");
		JSONObject portJson = getVertByName("3629", vertices);
		assertEquals(portJson.get("vertexType"), "Observable");
		assertEquals(portJson.get("description").toString(), "[\"3629\"]");
		assertEquals(portJson.get("source").toString(), "[\"Situ\"]");
		assertEquals(portJson.get("observableType"), "Port");
		observableString = portJson.getString("sourceDocument");
		observable = new Observable().fromXMLString(observableString);
		assertTrue(observable.validate());

		System.out.println("Testing Port ... ");
		portJson = getVertByName("443", vertices);
		assertEquals(portJson.get("vertexType"), "Observable");
		assertEquals(portJson.get("description").toString(), "[\"443\"]");
		assertEquals(portJson.get("source").toString(), "[\"Situ\"]");
		assertEquals(portJson.get("observableType"), "Port");
		observableString = portJson.getString("sourceDocument");
		observable = new Observable().fromXMLString(observableString);
		assertTrue(observable.validate());

		System.out.println("Testing Address ... ");
		JSONObject addressJson = getVertByName("89.44.100.114:3629", vertices);
		assertEquals(addressJson.get("vertexType"), "Observable");
		assertEquals(addressJson.get("description").toString(), "[\"89.44.100.114, port 3629\"]");
		assertEquals(addressJson.get("source").toString(), "[\"Situ\"]");
		assertEquals(addressJson.get("observableType"), "Socket Address");
		observableString = addressJson.getString("sourceDocument");
		observable = new Observable().fromXMLString(observableString);
		assertTrue(observable.validate());

		System.out.println("Testing Address ... ");
		addressJson = getVertByName("100.1.10.101:443", vertices);
		assertEquals(addressJson.get("vertexType"), "Observable");
		assertEquals(addressJson.get("description").toString(), "[\"100.1.10.101, port 443\"]");
		assertEquals(addressJson.get("source").toString(), "[\"Situ\"]");
		assertEquals(addressJson.get("observableType"), "Socket Address");
		observableString = addressJson.getString("sourceDocument");
		observable = new Observable().fromXMLString(observableString);
		assertTrue(observable.validate());

		System.out.println("Testing Flow ... ");
		JSONObject flowJson = getVertByName("89.44.100.114:3629_through_100.1.10.101:443", vertices);
		assertEquals(flowJson.get("vertexType"), "Observable");
		assertEquals(flowJson.get("description").toString(), "[\"89.44.100.114, port 3629 to 100.1.10.101, port 443\"]");
		assertEquals(flowJson.get("source").toString(), "[\"Situ\"]");
		assertEquals(flowJson.get("observableType"), "Network Flow");
		observableString = flowJson.getString("sourceDocument");
		observable = new Observable().fromXMLString(observableString);
		assertTrue(observable.validate());

		System.out.println("Testing Address -> IP ... ");
		String addressID = getVertIDByName("89.44.100.114:3629", vertices);
		String ipID = getVertIDByName("89.44.100.114", vertices);
		JSONObject expectedEdge = getEdgeByProps(addressID, ipID, "Sub-Observable", edges);
		assertNotNull(expectedEdge); 

		System.out.println("Testing Address -> Port ... ");
		addressID = getVertIDByName("89.44.100.114:3629", vertices);
		String portID = getVertIDByName("3629", vertices);
		expectedEdge = getEdgeByProps(addressID, portID, "Sub-Observable", edges);
		assertNotNull(expectedEdge);

		System.out.println("Testing Address -> IP ... ");
		addressID = getVertIDByName("100.1.10.101:443", vertices);
		ipID = getVertIDByName("100.1.10.101", vertices);
		expectedEdge = getEdgeByProps(addressID, ipID, "Sub-Observable", edges);
		assertNotNull(expectedEdge); 

		System.out.println("Testing Address -> Port ... ");
		addressID = getVertIDByName("100.1.10.101:443", vertices);
		portID = getVertIDByName("443", vertices);
		expectedEdge = getEdgeByProps(addressID, portID, "Sub-Observable", edges);
		assertNotNull(expectedEdge);

		System.out.println("Testing Flow -> Src Address ... ");
		String flowID = getVertIDByName("89.44.100.114:3629_through_100.1.10.101:443", vertices);
		addressID = getVertIDByName("89.44.100.114:3629", vertices);
		expectedEdge = getEdgeByProps(flowID, addressID, "Sub-Observable", edges);
		assertNotNull(expectedEdge); 

		System.out.println("Testing Flow -> Dst Address ... ");
		flowID = getVertIDByName("89.44.100.114:3629_through_100.1.10.101:443", vertices);
		addressID = getVertIDByName("100.1.10.101:443", vertices);
		expectedEdge = getEdgeByProps(flowID, addressID, "Sub-Observable", edges);
		assertNotNull(expectedEdge); 
	}

	/**
	 * Test two entries with duplicates
	 */
	@Test
	public void test_two_entries() throws SAXException {
		String situInfo = 
		"{ \"uuid\":\"e6482023-7834-5fe4-85e8-edb58cc00075\",\"raw\":\"tcp,RST,0.0.0.0,2006-10-01T18:48:15.399585,2006-10-01T18:48:15.441310,0.041725,92.6.85.110,   -\u003e,100.20.200.15,3528,443,18,2333,0,0.000000,,,,,,, e        ,1,Mws   T,0,961,10,0.000000,6910,165847.812500,0,1372,8,0.000000,5792,230269.625000,,0.000876,GB,US,,,-0.000000,\",\"sourceType\":\"argus\",\"sourceName\":\"jg\",\"contextScores\":[{ \"name\":\"Pcr\",\"score\":1.757244e-05},{ \"name\":\"Pcr_T\",\"score\":1.757244e-05},{ \"name\":\"PrivPorts\",\"score\":1.9143281e-05},{ \"name\":\"PrivPorts_T\",\"score\":1.9143281e-05}],\"score\":1.9143281e-05,\"stime\":\"2006-10-01T18:48:15.399585\",\"ltime\":\"2006-10-01T18:48:15.44131\",\"duration\":0.041725,\"sip\":\"92.6.85.110\",\"sport\":3528,\"dip\":\"100.20.200.15\",\"dport\":443,\"sco\":\"GB\",\"dco\":\"US\",\"sloc\":{ \"location\":{}},\"dloc\":{ \"location\":{}},\"pkts\":18,\"spkts\":10,\"dpkts\":8,\"bytes\":2333,\"sbytes\":961,\"dbytes\":1372,\"swin\":6910,\"dwin\":5792,\"sload\":165847.81,\"dload\":230269.62,\"proto\":\"tcp\",\"state\":\"RST\",\"srcid\":\"0.0.0.0\",\"flgs\":\" e        \",\"trans\":1,\"tcpopt\":\"Mws   T\",\"tcprtt\":0.000876,\"pcr\":-0.17616802,\"created\":\"2016-08-17T14:35:36.382131\",\"direction\":\"   -\u003e\"}" + "\n " +
		"{ \"uuid\":\"60e628da-a543-56db-9d86-1e322dc90d2e\",\"raw\":\"tcp,FIN,0.0.0.0,2006-10-01T18:48:15.620432,2006-10-01T18:48:15.867863,0.247431,100.20.140.253,   -\u003e,100.1.10.25,28653,110,19,1527,0,0.000000,,,,,,, e        ,1,Mws   T,0,708,10,0.000000,5840,20627.972656,0,819,9,0.000000,5792,23537.875000,,0.000238,US,US,,,-0.000000,\",\"sourceType\":\"argus\",\"sourceName\":\"jg\",\"contextScores\":[{ \"name\":\"Pcr\",\"score\":0.001635761},{ \"name\":\"Pcr_T\",\"score\":1.9130632e-05},{ \"name\":\"PrivPorts\",\"score\":0.14166467},{ \"name\":\"PrivPorts_T\",\"score\":0.14166467},{ \"name\":\"BytesPerPacket\",\"score\":0.32975367},{ \"name\":\"BytesPerPacket_T\",\"score\":0.32975367}],\"score\":0.32975367,\"stime\":\"2006-10-01T18:48:15.620432\",\"ltime\":\"2006-10-01T18:48:15.867863\",\"duration\":0.247431,\"sip\":\"100.20.140.253\",\"sport\":28653,\"dip\":\"92.6.85.110\",\"dport\":3528,\"sco\":\"US\",\"dco\":\"US\",\"sloc\":{ \"location\":{}},\"dloc\":{ \"location\":{}},\"pkts\":19,\"spkts\":10,\"dpkts\":9,\"bytes\":1527,\"sbytes\":708,\"dbytes\":819,\"swin\":5840,\"dwin\":5792,\"sload\":20627.973,\"dload\":23537.875,\"proto\":\"tcp\",\"state\":\"FIN\",\"srcid\":\"0.0.0.0\",\"flgs\":\" e        \",\"trans\":1,\"tcpopt\":\"Mws   T\",\"tcprtt\":0.000238,\"pcr\":-0.07269155,\"created\":\"2016-08-17T14:35:36.382276\",\"direction\":\"   -\u003e\"}";

		SituGraphExtractor situExtractor = new SituGraphExtractor(situInfo);
		JSONObject graph = situExtractor.getGraph();

		JSONObject vertices = graph.getJSONObject("vertices");
		JSONArray edges = graph.getJSONArray("edges");

		assertEquals(vertices.length(), 11);
		assertEquals(edges.length(), 10);

		System.out.println("Testing IP ... ");
		JSONObject ipJson = getVertByName("100.20.140.253", vertices);
		assertEquals(ipJson.get("vertexType"), "IP");
		assertEquals(ipJson.get("description").toString(), "[\"100.20.140.253\"]");
		assertEquals(ipJson.get("ipInt"), ExtractorUtils.ipToLong("100.20.140.253"));
		assertEquals(ipJson.get("source").toString(), "[\"Situ\"]");
		assertEquals(ipJson.get("observableType"), "Address");
		String observableString = ipJson.getString("sourceDocument");
		Observable observable = new Observable().fromXMLString(observableString);
		assertTrue(observable.validate());

		System.out.println("Testing IP ... ");
		ipJson = getVertByName("92.6.85.110", vertices);
		assertEquals(ipJson.get("vertexType"), "IP");
		assertEquals(ipJson.get("description").toString(), "[\"92.6.85.110\"]");
		assertEquals(ipJson.get("ipInt"), ExtractorUtils.ipToLong("92.6.85.110"));
		assertEquals(ipJson.get("source").toString(), "[\"Situ\"]");
		assertEquals(ipJson.get("observableType"), "Address");
		observableString = ipJson.getString("sourceDocument");
		observable = new Observable().fromXMLString(observableString);
		assertTrue(observable.validate());

		System.out.println("Testing IP ... ");
		ipJson = getVertByName("100.20.200.15", vertices);
		assertEquals(ipJson.get("vertexType"), "IP");
		assertEquals(ipJson.get("description").toString(), "[\"100.20.200.15\"]");
		assertEquals(ipJson.get("ipInt"), ExtractorUtils.ipToLong("100.20.200.15"));
		assertEquals(ipJson.get("source").toString(), "[\"Situ\"]");
		assertEquals(ipJson.get("observableType"), "Address");
		observableString = ipJson.getString("sourceDocument");
		observable = new Observable().fromXMLString(observableString);
		assertTrue(observable.validate());

		System.out.println("Testing Port ... ");
		JSONObject portJson = getVertByName("28653", vertices);
		assertEquals(portJson.get("vertexType"), "Observable");
		assertEquals(portJson.get("description").toString(), "[\"28653\"]");
		assertEquals(portJson.get("source").toString(), "[\"Situ\"]");
		assertEquals(portJson.get("observableType"), "Port");
		observableString = portJson.getString("sourceDocument");
		observable = new Observable().fromXMLString(observableString);
		assertTrue(observable.validate());

		System.out.println("Testing Port ... ");
		portJson = getVertByName("3528", vertices);
		assertEquals(portJson.get("vertexType"), "Observable");
		assertEquals(portJson.get("description").toString(), "[\"3528\"]");
		assertEquals(portJson.get("source").toString(), "[\"Situ\"]");
		assertEquals(portJson.get("observableType"), "Port");
		observableString = portJson.getString("sourceDocument");
		observable = new Observable().fromXMLString(observableString);
		assertTrue(observable.validate());

		System.out.println("Testing Port ... ");
		portJson = getVertByName("443", vertices);
		assertEquals(portJson.get("vertexType"), "Observable");
		assertEquals(portJson.get("description").toString(), "[\"443\"]");
		assertEquals(portJson.get("source").toString(), "[\"Situ\"]");
		assertEquals(portJson.get("observableType"), "Port");
		observableString = portJson.getString("sourceDocument");
		observable = new Observable().fromXMLString(observableString);
		assertTrue(observable.validate());

		System.out.println("Testing Address ... ");
		JSONObject addressJson = getVertByName("100.20.140.253:28653", vertices);
		assertEquals(addressJson.get("vertexType"), "Observable");
		assertEquals(addressJson.get("description").toString(), "[\"100.20.140.253, port 28653\"]");
		assertEquals(addressJson.get("source").toString(), "[\"Situ\"]");
		assertEquals(addressJson.get("observableType"), "Socket Address");
		observableString = addressJson.getString("sourceDocument");
		observable = new Observable().fromXMLString(observableString);
		assertTrue(observable.validate());

		System.out.println("Testing Address ... ");
		addressJson = getVertByName("92.6.85.110:3528", vertices);
		assertEquals(addressJson.get("vertexType"), "Observable");
		assertEquals(addressJson.get("description").toString(), "[\"92.6.85.110, port 3528\"]");
		assertEquals(addressJson.get("source").toString(), "[\"Situ\"]");
		assertEquals(addressJson.get("observableType"), "Socket Address");
		observableString = addressJson.getString("sourceDocument");
		observable = new Observable().fromXMLString(observableString);
		assertTrue(observable.validate());

		System.out.println("Testing Address ... ");
		addressJson = getVertByName("100.20.200.15:443", vertices);
		assertEquals(addressJson.get("vertexType"), "Observable");
		assertEquals(addressJson.get("description").toString(), "[\"100.20.200.15, port 443\"]");
		assertEquals(addressJson.get("source").toString(), "[\"Situ\"]");
		assertEquals(addressJson.get("observableType"), "Socket Address");
		observableString = addressJson.getString("sourceDocument");
		observable = new Observable().fromXMLString(observableString);
		assertTrue(observable.validate());

		System.out.println("Testing Flow ... ");
		JSONObject flowJson = getVertByName("100.20.140.253:28653_through_92.6.85.110:3528", vertices);
		assertEquals(flowJson.get("vertexType"), "Observable");
		assertEquals(flowJson.get("description").toString(), "[\"100.20.140.253, port 28653 to 92.6.85.110, port 3528\"]");
		assertEquals(flowJson.get("source").toString(), "[\"Situ\"]");
		assertEquals(flowJson.get("observableType"), "Network Flow");
		observableString = flowJson.getString("sourceDocument");
		observable = new Observable().fromXMLString(observableString);
		assertTrue(observable.validate());

		System.out.println("Testing Flow ... ");
		flowJson = getVertByName("92.6.85.110:3528_through_100.20.200.15:443", vertices);
		assertEquals(flowJson.get("vertexType"), "Observable");
		assertEquals(flowJson.get("description").toString(), "[\"92.6.85.110, port 3528 to 100.20.200.15, port 443\"]");
		assertEquals(flowJson.get("source").toString(), "[\"Situ\"]");
		assertEquals(flowJson.get("observableType"), "Network Flow");
		observableString = flowJson.getString("sourceDocument");
		observable = new Observable().fromXMLString(observableString);
		assertTrue(observable.validate());

		System.out.println("Testing Address -> IP ... ");
		String addressID = getVertIDByName("100.20.140.253:28653", vertices);
		String ipID = getVertIDByName("100.20.140.253", vertices);
		JSONObject expectedEdge = getEdgeByProps(addressID, ipID, "Sub-Observable", edges);
		assertNotNull(expectedEdge); 

		System.out.println("Testing Address -> Port ... ");
		addressID = getVertIDByName("100.20.140.253:28653", vertices);
		String portID = getVertIDByName("28653", vertices);
		expectedEdge = getEdgeByProps(addressID, portID, "Sub-Observable", edges);
		assertNotNull(expectedEdge);

		System.out.println("Testing Address -> IP ... ");
		addressID = getVertIDByName("92.6.85.110:3528", vertices);
		ipID = getVertIDByName("3528", vertices);
		expectedEdge = getEdgeByProps(addressID, ipID, "Sub-Observable", edges);
		assertNotNull(expectedEdge); 

		System.out.println("Testing Address -> Port ... ");
		addressID = getVertIDByName("92.6.85.110:3528", vertices);
		portID = getVertIDByName("3528", vertices);
		expectedEdge = getEdgeByProps(addressID, portID, "Sub-Observable", edges);
		assertNotNull(expectedEdge);

		System.out.println("Testing Address -> IP ... ");
		addressID = getVertIDByName("100.20.200.15:443", vertices);
		ipID = getVertIDByName("100.20.200.15", vertices);
		expectedEdge = getEdgeByProps(addressID, ipID, "Sub-Observable", edges);
		assertNotNull(expectedEdge); 

		System.out.println("Testing Address -> Port ... ");
		addressID = getVertIDByName("100.20.200.15:443", vertices);
		portID = getVertIDByName("443", vertices);
		expectedEdge = getEdgeByProps(addressID, portID, "Sub-Observable", edges);
		assertNotNull(expectedEdge);

		System.out.println("Testing Flow -> Src Address ... ");
		String flowID = getVertIDByName("100.20.140.253:28653_through_92.6.85.110:3528", vertices);
		addressID = getVertIDByName("100.20.140.253:28653", vertices);
		expectedEdge = getEdgeByProps(flowID, addressID, "Sub-Observable", edges);
		assertNotNull(expectedEdge); 

		System.out.println("Testing Flow -> Dst Address ... ");
		flowID = getVertIDByName("100.20.140.253:28653_through_92.6.85.110:3528", vertices);
		addressID = getVertIDByName("92.6.85.110:3528", vertices);
		expectedEdge = getEdgeByProps(flowID, addressID, "Sub-Observable", edges);
		assertNotNull(expectedEdge); 

		System.out.println("Testing Flow -> Src Address ... ");
		flowID = getVertIDByName("92.6.85.110:3528_through_100.20.200.15:443", vertices);
		addressID = getVertIDByName("92.6.85.110:3528", vertices);
		expectedEdge = getEdgeByProps(flowID, addressID, "Sub-Observable", edges);
		assertNotNull(expectedEdge); 

		System.out.println("Testing Flow -> Dst Address ... ");
		flowID = getVertIDByName("92.6.85.110:3528_through_100.20.200.15:443", vertices);
		addressID = getVertIDByName("100.20.200.15:443", vertices);
		expectedEdge = getEdgeByProps(flowID, addressID, "Sub-Observable", edges);
		assertNotNull(expectedEdge); 

		assertTrue(true);
	}

	/**
	 * Test large file
	 */
	//@Test
	public void test_large_file()	throws FileNotFoundException, IOException {
		File file = new File("./data/skaion.json");
		BufferedReader br = new BufferedReader(new FileReader(file));
 		String situInfo = org.apache.commons.io.IOUtils.toString(br);
		SituGraphExtractor situExtractor = new SituGraphExtractor(situInfo);
		JSONObject graph = situExtractor.getGraph();
		br.close();
	}
}
