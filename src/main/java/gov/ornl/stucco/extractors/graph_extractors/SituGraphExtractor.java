package gov.ornl.stucco.graph_extractors;

import gov.ornl.stucco.utils.ExtractorUtils;
import gov.ornl.stucco.utils.GraphUtils;

import java.util.Set;
import java.util.HashSet;
import java.util.UUID;
import java.util.Map;
import java.util.HashMap;

import java.io.IOException;
import java.io.BufferedReader;
import java.io.StringReader;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.json.JSONObject;
import org.json.JSONArray;
 
/**
 * Situ data to graph extractor.
 *
 * @author Maria Vincent
 */
public class SituGraphExtractor {
						
	private static final Logger logger = LoggerFactory.getLogger(SituGraphExtractor.class);
	private static final String SIP = "sip";
	private static final String SPORT = "sport";
	private static final String DIP = "dip";
	private static final String DPORT = "dport";
	private static final String PROTO = "proto";
	
	private JSONObject graph = null;
	
	public SituGraphExtractor(String situInfo) {
		graph = extract(situInfo);
	}
					
	public JSONObject getGraph() {
		return graph;
	}

	private JSONObject extract (String situInfo) {
		JSONObject vertices = new JSONObject();
		JSONArray edges = new JSONArray();
		graph = new JSONObject();
		graph.put("vertices", vertices);
		graph.put("edges", edges);

		/* presetting source set to use as a source field in every vertex */		
		Set<String> source = new HashSet<String>();
		source.add("Situ");
		/* map to store vertex names -> vertex ids; used for duplicate detection */
		Map<String, String> vertNames = new HashMap<String, String>();

		try {
			BufferedReader bufReader = new BufferedReader(new StringReader(situInfo));
			String line = null;
			while ((line = bufReader.readLine()) != null) {
				JSONObject entry = new JSONObject(line);

				String srcIp = null;
				String srcPort = null;
				String dstIp = null;
				String dstPort = null;
				String flow = null;

				String srcIpID = null;
				String srcPortID = null;
				String dstIpID = null;
				String dstPortID = null;
				String srcAddressID = null;
				String dstAddressID = null;
				String flowID = null;

				/* source ip */			
				if (entry.has(SIP)) {
					srcIp = entry.getString(SIP);
					if (vertNames.containsKey(srcIp)) {
						srcIpID = vertNames.get(srcIp);
					} else {
						srcIpID = UUID.randomUUID().toString();
						JSONObject srcIpJson = GraphUtils.setIpJson(srcIp, srcIpID, source, "Situ");
						vertices.put(srcIpID, srcIpJson);
						vertNames.put(srcIp, srcIpID);
					}
				}

				/* source port */
					if (entry.has(SPORT)) {
					srcPort = entry.get(SPORT).toString();
					if (vertNames.containsKey(srcPort)) {
						srcPortID = vertNames.get(srcPort);
					} else {
						srcPortID = UUID.randomUUID().toString();
						JSONObject srcPortJson = GraphUtils.setPortJson(srcPort, source, "Situ");
						vertices.put(srcPortID, srcPortJson);
						vertNames.put(srcPort, srcPortID);
					}
				}

				/* destination ip */
				if (entry.has(DIP)) {
					dstIp = entry.getString(DIP);
					if (vertNames.containsKey(dstIp)) {
						dstIpID = vertNames.get(dstIp);
					} else {
						dstIpID = UUID.randomUUID().toString();
						JSONObject dstIpJson = GraphUtils.setIpJson(dstIp, dstIpID, source, "Situ");
						vertices.put(dstIpID, dstIpJson);
						vertNames.put(dstIpID, dstIp);
					}
				}

				/* destination port */
				if (entry.has(DPORT)) {
					dstPort = entry.get(DPORT).toString();
					if (vertNames.containsKey(dstPort)) {
						dstPortID = vertNames.get(dstPort);
					} else {
						dstPortID = UUID.randomUUID().toString();
						JSONObject dstPortJson = GraphUtils.setPortJson(dstPort, source, "Situ");
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
						srcAddressID = UUID.randomUUID().toString();
						JSONObject srcAddressJson = GraphUtils.setAddressJson(srcIp, srcIpID, srcPort, srcPortID, source, "Situ");
						vertices.put(srcAddressID, srcAddressJson);
						vertNames.put(address, srcAddressID);
						/* address -> ip edge */
						JSONObject edge = GraphUtils.setEdgeJson(srcAddressID, "Observable", srcIpID, "IP", "Sub-Observable");
						edges.put(edge);
						/* address -> port edge */
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
						dstAddressID = UUID.randomUUID().toString();
						JSONObject dstAddressJson = GraphUtils.setAddressJson(dstIp, dstIpID, dstPort, dstPortID, source, "Situ");
						vertices.put(dstAddressID, dstAddressJson);
						vertNames.put(address, dstAddressID);
						/* address -> ip edge */
						JSONObject edge = GraphUtils.setEdgeJson(dstAddressID, "Observable", dstIpID, "IP", "Sub-Observable");
						edges.put(edge);                      
						/* address -> port edge */                                                                                                    
						edge = GraphUtils.setEdgeJson(dstAddressID, "Observable", dstPortID, "Observable", "Sub-Observable");
						edges.put(edge);
					}
				}

				/* flow */
				if (srcAddressID != null && dstAddressID != null) {
					flow = GraphUtils.buildString(srcIp, ":", srcPort, "_through_", dstIp, ":", dstPort);
					if (vertNames.containsKey(flow)) {
						flowID = vertNames.get(flow);
					} else {
						flowID = UUID.randomUUID().toString();
						String protocol = entry.opt(PROTO).toString();
						JSONObject flowJson = GraphUtils.setFlowJson(flowID, srcIp, srcPort, srcAddressID, dstIp, dstPort, dstAddressID, protocol, source, "Situ", entry);
						vertices.put(flowID, flowJson);
						vertNames.put(flowJson.getString("name"), flowID);
						/* flow -> src address edge */
						JSONObject edge = GraphUtils.setEdgeJson(flowID, "Observable", srcAddressID, "Observable", "Sub-Observable");
						edges.put(edge);
						/* flow -> dst address edge */
						edge = GraphUtils.setEdgeJson(flowID, "Observable", dstAddressID, "Observable", "Sub-Observable");
						edges.put(edge);
					}
				}
			}
		} catch (IOException e) {
			e.printStackTrace();
		}

		return (vertices.length() == 0 && edges.length() == 0) ? null : graph;
	}
}
