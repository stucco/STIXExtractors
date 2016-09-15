package gov.ornl.stucco.graph_extractors;

import gov.ornl.stucco.utils.ExtractorUtils;
import gov.ornl.stucco.utils.GraphUtils;

import java.util.HashSet;
import java.util.Set;
import java.util.Map;
import java.util.HashMap;
import java.util.List; 
import java.util.UUID;
  
import java.io.IOException;
 
import org.apache.commons.csv.CSVRecord; 
 
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.json.JSONObject;
import org.json.JSONArray;
 
/**
 * Argus data to STIX format extractor.
 *
 * @author Maria Vincent
 */
public class ArgusGraphExtractor {
						
	private static final Logger logger = LoggerFactory.getLogger(ArgusGraphExtractor.class);
	private static final String PROTOCOL ="Proto";
	private static final String SOURCE_ADDRESS ="SrcAddr";
	private static final String SOURCE_PORT = "Sport";
	private static final String DESTINATION_ADDRESS ="DstAddr";
	private static final String DESTINATION_PORT ="Dport";
	private static final String STATE ="State";

	private String[] HEADERS = null;
	private HashSet<String> headersSet;
	private JSONObject graph = null;
	
	public ArgusGraphExtractor(final String[] HEADERS, String argusInfo) {
		this.HEADERS = HEADERS.clone();
		initHeadersSet();
		graph = extract(argusInfo);
	}
					
	public JSONObject getGraph() {
		return graph;
	}

	/* making a set of headers that would go into custom fields */
	private void initHeadersSet() {
		headersSet = new HashSet<String>();		
		
		for (int i = 0; i < HEADERS.length; i++) {
			headersSet.add(HEADERS[i]);
		}
		
		headersSet.remove(PROTOCOL);
		headersSet.remove(SOURCE_ADDRESS);
		headersSet.remove(SOURCE_PORT);
		headersSet.remove(DESTINATION_ADDRESS);
		headersSet.remove(DESTINATION_PORT);
	}

	private JSONObject extract (String argusInfo) {
		List<CSVRecord> records;
		try {
			records = ExtractorUtils.getCSVRecordsList(HEADERS, argusInfo);
		} catch (IOException e) {
			e.printStackTrace();
			return null;
		}	
		if (records.isEmpty()) {
			return null;
		}

		CSVRecord record = records.get(0);
		int start;
		if (record.get(0).equals(HEADERS[0]))	{
			if (records.size() == 1) {
				return null;
			} else {
				start = 1;
			}
		} else {
			start = 0;
		}

		JSONObject vertices = new JSONObject();
		JSONArray edges = new JSONArray();
		graph = new JSONObject();
		graph.put("vertices", vertices);
		graph.put("edges", edges);
		Map<String, String> vertNames = new HashMap<String, String>();
		Set<String> source = new HashSet<String>();
		source.add("Argus");
						
	 	for (int i = start; i < records.size(); i++) {
	 		try {
				record = records.get(i);

				String srcIp = null;
				String srcPort = null;
				String dstIp = null;
				String dstPort = null;

				String srcIpID = null;
				String srcPortID = null;
				String dstIpID = null;
				String dstPortID = null;
				String srcAddressID = null;
				String dstAddressID = null;
				String flowID = null;
							
				/* source ip */			
				if (!record.get(SOURCE_ADDRESS).isEmpty()) {
					srcIp = record.get(SOURCE_ADDRESS);
					if (vertNames.containsKey(srcIp)) {
						srcIpID = vertNames.get(srcIp);
					} else {
						srcIpID = GraphUtils.buildString("stucco:Observable-", UUID.randomUUID());
						JSONObject srcIpJson = GraphUtils.setIpJson(srcIpID, srcIp, source, "Argus");
						vertices.put(srcIpID, srcIpJson);
						vertNames.put(srcIp, srcIpID);
					}
				}

				/* source port */
					if (!record.get(SOURCE_PORT).isEmpty()) {
					srcPort = record.get(SOURCE_PORT);
					if (vertNames.containsKey(srcPort)) {
						srcPortID = vertNames.get(srcPort);
					} else {
						srcPortID = GraphUtils.buildString("stucco:Observable-", UUID.randomUUID());
						JSONObject srcPortJson = GraphUtils.setPortJson(srcPortID, srcPort, source, "Argus");
						vertices.put(srcPortID, srcPortJson);
						vertNames.put(srcPort, srcPortID);
					}
				}

				/* destination ip */
				if (!record.get(DESTINATION_ADDRESS).isEmpty()) {
					dstIp = record.get(DESTINATION_ADDRESS);
					if (vertNames.containsKey(dstIp)) {
						dstIpID = vertNames.get(dstIp);
					} else {
						dstIpID = GraphUtils.buildString("stucco:Observable-", UUID.randomUUID());
						JSONObject dstIpJson = GraphUtils.setIpJson(dstIpID, dstIp, source, "Argus");
						vertices.put(dstIpID, dstIpJson);
						vertNames.put(dstIpID, dstIp);
					}
				}

				/* destination port */
				if (!record.get(DESTINATION_PORT).isEmpty()) {
					dstPort = record.get(DESTINATION_PORT);
					if (vertNames.containsKey(dstPort)) {
						dstPortID = vertNames.get(dstPort);
					} else {
						dstPortID = GraphUtils.buildString("stucco:Observable-", UUID.randomUUID());
						JSONObject dstPortJson = GraphUtils.setPortJson(dstPortID, dstPort, source, "Argus");
						vertices.put(dstPortID, dstPortJson);
						vertNames.put(dstPort, dstPortID);
					}
				}

				/* source address */
				if (srcIpID != null && srcPortID != null) {
					String address = GraphUtils.buildString(srcIp, ":", srcPort);
					if (vertNames.containsKey(address)) {
						srcAddressID = vertNames.get(address);
					} else {
						srcAddressID = GraphUtils.buildString("stucco:Observable-", UUID.randomUUID());
						JSONObject srcAddressJson = GraphUtils.setAddressJson(srcAddressID, srcIp, srcIpID, srcPort, srcPortID, source, "Argus");
						vertices.put(srcAddressID, srcAddressJson);
						vertNames.put(address, srcAddressID);
						/* source address -> ip edge */
						JSONObject edge = GraphUtils.setEdgeJson(srcAddressID,  "Observable", srcIpID, "IP", "Sub-Observable");
						edges.put(edge);
						/* source address -> port edge */
						edge = GraphUtils.setEdgeJson(srcAddressID, "Observable", srcPortID, "Observable", "Sub-Observable");
						edges.put(edge);
					}
				}

				/* destination address */
				if (dstIpID != null && dstPortID != null) {
					String address = GraphUtils.buildString(dstIp, ":", dstPort);
					if (vertNames.containsKey(address)) {
						dstAddressID = vertNames.get(address);
					} else {
						dstAddressID = GraphUtils.buildString("stucco:Observable-", UUID.randomUUID());
						JSONObject dstAddressJson = GraphUtils.setAddressJson(dstAddressID, dstIp, dstIpID, dstPort, dstPortID, source, "Argus");
						vertices.put(dstAddressID, dstAddressJson);
						vertNames.put(address, dstAddressID);
						/* destination address -> ip edge */
						JSONObject edge = GraphUtils.setEdgeJson(dstAddressID, "Observable", dstIpID, "IP", "Sub-Observable");
						edges.put(edge);                        
						/* destination address -> port edge */                                                                                                  
						edge = GraphUtils.setEdgeJson(dstAddressID, "Observable", dstPortID, "Observable", "Sub-Observable");
						edges.put(edge);
					}
				}

				/* flow */
				if (srcAddressID != null && dstAddressID != null) {
					String flow = GraphUtils.buildString(srcIp, ":", srcPort, "_through_", dstIp, ":", dstPort);
					if (vertNames.containsKey(flow)) {
						flowID = vertNames.get(flow);
					} else {
						flowID = GraphUtils.buildString("stucco:Observable-", UUID.randomUUID());
						String protocol = (record.get(PROTOCOL).isEmpty()) ? null : record.get(PROTOCOL);
						JSONObject flowJson = GraphUtils.setFlowJson(flowID, srcIp, srcPort, srcAddressID, dstIp, dstPort, dstAddressID, protocol, source, "Argus", record, headersSet);
						vertices.put(flowID, flowJson);
						vertNames.put(flowJson.getString("name"), flowID);
						/* flow -> source address edge */
						JSONObject edge = GraphUtils.setEdgeJson(flowID, "Observable", srcAddressID, "Observable", "Sub-Observable");
						edges.put(edge);
						/* flow -> destination address edge */
						edge = GraphUtils.setEdgeJson(flowID, "Observable", dstAddressID, "Observable", "Sub-Observable");
						edges.put(edge);
					}
				}
			} catch (RuntimeException e) {
				e.printStackTrace();
			}
		}

		return (vertices.length() == 0 && edges.length() == 0) ? null : graph;
	}
}