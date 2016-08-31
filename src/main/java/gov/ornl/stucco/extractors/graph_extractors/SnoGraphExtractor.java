package gov.ornl.stucco.graph_extractors;

import gov.ornl.stucco.utils.ExtractorUtils;
import gov.ornl.stucco.utils.GraphUtils;

import java.util.HashSet;
import java.util.Set;
import java.util.Map;
import java.util.HashMap;
import java.util.List; 
import java.util.UUID;
import java.util.Calendar;
import java.util.GregorianCalendar;
 
import javax.xml.bind.DatatypeConverter;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.XMLGregorianCalendar;
 
import java.io.IOException;
 
import org.apache.commons.csv.CSVRecord;
 
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.json.JSONObject;
import org.json.JSONArray;
 
/**
 * Sno data to STIX format extractor.
 *
 * @author Maria Vincent
 */
public class SnoGraphExtractor {
	
 
						
	private static final Logger logger = LoggerFactory.getLogger(SnoGraphExtractor.class);
	private static final String[] HEADERS = {"file_name", "rec_num", "timet", "site", "proto", "saddr", "daddr", "sport", "dport", "alert_id", "alert_rev", "alert_msg", "icmp_type", 
																		"icmp_code", "gen_id", "scountrycode", "sorganization", "slat", "slong", "dcountrycode", "dorganization", "dlat", "dlong", "distance"};
	private static final String[] CUSTOM_FIELDS = {"timet", "site", "alert_id", "alert_rev", "alert_msg", "icmp_type", "icmp_code", "gen_id"};
	private static final String FILE_NAME = "file_name";
	private static final String REC_NUM = "rec_num";
	private static final String TIMET = "timet";
	private static final String SITE = "site";
	private static final String PROTO = "proto";
	private static final String SADDR = "saddr";
	private static final String DADDR = "daddr";
	private static final String SPORT = "sport";
	private static final String DPORT = "dport";
	private static final String ALERT_ID = "alert_id";
	private static final String ALERT_REV = "alert_rev";
	private static final String ALERT_MSG = "alert_msg";												
	private static final String ICMP_TYPE = "icmp_type";
	private static final String ICMP_CODE = "icmp_code";
	private static final String GEN_ID = "gen_id";
	private static final String SCOUNTRYCODE = "scountrycode";
	private static final String SORGANIZATION = "sorganization";
	private static final String SLAT = "slat";
	private static final String SLONG = "slong";
	private static final String DCOUNTRYCODE = "dcountrycode";
	private static final String DORGANIZATION = "dorganization";
	private static final String DLAT = "dlat";
	private static final String DLONG = "dlong";
	private static final String DISTANCE = "distance";

	private JSONObject graph = null;
	
	public SnoGraphExtractor(String snoInfo) { 
		graph = extract(snoInfo);
	}
					
	public JSONObject getGraph() {
		return graph;
	}

	private JSONObject extract (String snoInfo) {
		List<CSVRecord> records;
		try {
			records = ExtractorUtils.getCSVRecordsList(HEADERS, snoInfo);
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
		source.add("Sno");
						
	 	for (int i = start; i < records.size(); i++) {

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
			String indicatorID = null;

			/* dropping ipv6 for now */
			if (record.get(SADDR).contains(":") || record.get(DADDR).contains(":")) {
				continue;
			}
						
			/* source ip */			
			if (!record.get(SADDR).isEmpty()) {
				srcIp = record.get(SADDR);
				if (vertNames.containsKey(srcIp)) {
					srcIpID = vertNames.get(srcIp);
				} else {
					srcIpID = GraphUtils.buildString("stucco:Observable-", UUID.randomUUID());
					JSONObject srcIpJson = GraphUtils.setIpJson(srcIpID, srcIp, source, "Sno4");
					vertices.put(srcIpID, srcIpJson);
					vertNames.put(srcIp, srcIpID);
				}
			}

			/* source port */
				if (!record.get(SPORT).isEmpty()) {
				srcPort = record.get(SPORT);
				if (vertNames.containsKey(srcPort)) {
					srcPortID = vertNames.get(srcPort);
				} else {
					srcPortID = GraphUtils.buildString("stucco:Observable-", UUID.randomUUID());
					JSONObject srcPortJson = GraphUtils.setPortJson(srcPortID, srcPort, source, "Sno4");
					vertices.put(srcPortID, srcPortJson);
					vertNames.put(srcPort, srcPortID);
				}
			}

			/* destination ip */
			if (!record.get(DADDR).isEmpty()) {
				dstIp = record.get(DADDR);
				if (vertNames.containsKey(dstIp)) {
					dstIpID = vertNames.get(dstIp);
				} else {
					dstIpID = GraphUtils.buildString("stucco:Observable-", UUID.randomUUID());
					JSONObject dstIpJson = GraphUtils.setIpJson(dstIpID, dstIp, source, "Sno4");
					vertices.put(dstIpID, dstIpJson);
					vertNames.put(dstIpID, dstIp);
				}
			}

			/* destination port */
			if (!record.get(DPORT).isEmpty()) {
				dstPort = record.get(DPORT);
				if (vertNames.containsKey(dstPort)) {
					dstPortID = vertNames.get(dstPort);
				} else {
					dstPortID = GraphUtils.buildString("stucco:Observable-", UUID.randomUUID());
					JSONObject dstPortJson = GraphUtils.setPortJson(dstPortID, dstPort, source, "Sno4");
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
					JSONObject srcAddressJson = GraphUtils.setAddressJson(srcAddressID, srcIp, srcIpID, srcPort, srcPortID, source, "Sno4");
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
					JSONObject dstAddressJson = GraphUtils.setAddressJson(dstAddressID, dstIp, dstIpID, dstPort, dstPortID, source, "Sno4");
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
					String protocol = (record.get(PROTO).isEmpty()) ? null : record.get(PROTO);
					JSONObject flowJson = GraphUtils.setFlowJson(flowID, srcIp, srcPort, srcAddressID, dstIp, dstPort, dstAddressID, protocol, source, "Sno4", record, CUSTOM_FIELDS);
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
			
			/* indicator */
			if (flowID != null) {
				/* we do not compare indicators for now */
				indicatorID = GraphUtils.buildString("stucco:Indicator-", UUID.randomUUID());
				String alternativeID = record.get(ALERT_ID);
				XMLGregorianCalendar timestamp = (record.get(TIMET).isEmpty()) ? null : convertTimestamp(record.get(TIMET));
				String description = record.get(ALERT_MSG);
				Set<String> alias = new HashSet<String>();
				alias.add(vertices.getJSONObject(flowID).getString("name"));
				if (!record.get(ALERT_ID).isEmpty()) {
					alias.add(record.get(ALERT_ID));
				}
				JSONObject indicatorJson = GraphUtils.setIndicatorJson(indicatorID, alternativeID, timestamp, description, alias, flowID, source, "Sno4");
				vertices.put(indicatorID, indicatorJson);
				/* indicator -> flow observable edge */
				JSONObject edge = GraphUtils.setEdgeJson(indicatorID, "Indicator", flowID, "Observable", "Observable");
				edges.put(edge);
			}
		}

		return (vertices.length() == 0 && edges.length() == 0) ? null : graph;
	}

	public XMLGregorianCalendar convertTimestamp(String time)	{
		try {
			Calendar calendar = javax.xml.bind.DatatypeConverter.parseDateTime(time);
			GregorianCalendar gcalendar = new GregorianCalendar();
 			gcalendar.setTimeInMillis(calendar.getTimeInMillis());
	
			return DatatypeFactory.newInstance().newXMLGregorianCalendar(gcalendar);
		} catch (DatatypeConfigurationException e) {
			e.printStackTrace();
		}

		return null;
	}
}