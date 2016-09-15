package gov.ornl.stucco.graph_extractors;

import gov.ornl.stucco.utils.ExtractorUtils;
import gov.ornl.stucco.utils.GraphUtils;
import gov.ornl.stucco.utils.TemplatesUtils;

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
 * DNSRecord data to STIX format extractor.
 *
 * @author Maria Vincent
 */
public class DNSRecordGraphExtractor {
private static String[] HEADERS = {"filename", "recnum", "file_type", "amp_version", "site", "saddr", "daddr", "ttl", "rqtype", "flags", "rqfqdn",
					   "refqdn", "raddr", "preference", "answer_ns", "authoritative_ns", "times_seen", "first_seen_timet", "last_seen_timet", 
					   "scountrycode", "sorganization", "dcountrycode", "dorganization", "rcountrycode", "rorganization"};
	private static final String FILENAME = "filename";	
	private static final String SADDR = "saddr";	
	private static final String DADDR = "daddr";	
	private static final String TTL = "ttl";	
	private static final String RQTYPE = "rqtype";	
	private static final String FLAGS = "flags";	
	private static final String RQFQDN = "rqfqdn";	
	private static final String RADDR = "raddr";	
	private static final String LAST_SEEN_TIMET = "last_seen_timet";	

	private JSONObject graph = null;
	
	public DNSRecordGraphExtractor(String dnsInfo) {
		graph = extract(dnsInfo);
	}
					
	public JSONObject getGraph() {
		return graph;
	}

	private JSONObject extract (String dnsInfo) {
		List<CSVRecord> records;
		try {
			records = ExtractorUtils.getCSVRecordsList(HEADERS, dnsInfo);
		} catch (IOException e) {
			e.printStackTrace();
			return null;
		}
		if (records.isEmpty()) {
			return null;
		}

		CSVRecord record = records.get(0);
		int start;
		if (record.get(0).equals(FILENAME))	{
			if (records.size() == 1)	{
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
		Set<String> edgeNames = new HashSet<String>();
		Set<Object> source = new HashSet<Object>();
		source.add("DNSRecord");
	 	
		for (int i = start; i < records.size(); i++) {

			try {
				record = records.get(i);
				if (record.get(RQFQDN).isEmpty() && record.get(RADDR).isEmpty()) {
					continue;
				}
				
				String srcIpID = null;
				String dstIpID = null;
				String reqIpID = null;
				String dnsNameID = null;
				String dnsRecordID = null;

				String srcIp = null;
				String dstIp = null;
				String reqIp = null;
				String dnsName = null;
				String dnsRecordName = null;

				/* saddr (address of responding DNS server) */
				if (!record.get(SADDR).isEmpty()) {
					srcIp = record.get(SADDR);
					if (vertNames.containsKey(srcIp)) {
						srcIpID = vertNames.get(srcIp);
					} else {
						srcIpID = GraphUtils.buildString("stucco:Observable-", UUID.randomUUID());
						JSONObject srcIpJson = GraphUtils.setIpJson(srcIpID, srcIp, source, "DNSRecord");
						vertices.put(srcIpID, srcIpJson);
						vertNames.put(srcIp, srcIpID);
					}
				}

				/* daddr (address of DNS requester) */
				if (!record.get(DADDR).isEmpty()) {
					dstIp = record.get(DADDR);
					if (vertNames.containsKey(dstIp)) {
						dstIpID = vertNames.get(dstIp);
					} else {
						dstIpID = GraphUtils.buildString("stucco:Observable-", UUID.randomUUID());
						JSONObject dstIpJson = GraphUtils.setIpJson(dstIpID, dstIp, source, "DNSRecord");
						vertices.put(dstIpID, dstIpJson);
						vertNames.put(dstIp, dstIpID);
					}
				}
				
				/* raddr (requested address) */
				reqIp = record.get(RADDR);
				if (vertNames.containsKey(reqIp)) {
					reqIpID = vertNames.get(reqIp);
				} else {
					reqIpID = GraphUtils.buildString("stucco:Observable-", UUID.randomUUID());
					JSONObject reqIpJson = GraphUtils.setIpJson(reqIpID, reqIp, source, "DNSRecord");
					vertices.put(reqIpID, reqIpJson);
					vertNames.put(reqIp, reqIpID);
				}

				/* DNSName */
				dnsName = record.get(RQFQDN);
				if (vertNames.containsKey(dnsName)) {
					dnsNameID = vertNames.get(dnsName);
				} else {
					dnsNameID = GraphUtils.buildString("stucco:Observable-", UUID.randomUUID());
					JSONObject dnsNameJson = GraphUtils.setDNSNameJson(dnsNameID, dnsName, null, source, "DNSRecord");
					vertices.put(dnsNameID, dnsNameJson);
					vertNames.put(dnsName, dnsNameID);
				}

				/* DNS Record */
				dnsRecordName = GraphUtils.buildString(dnsName, "_resolved_to_", reqIp);
				if (vertNames.containsKey(dnsRecordName)) {
					dnsRecordID = vertNames.get(dnsRecordName);
				} else {
					dnsRecordID = GraphUtils.buildString("stucco:Observable-", UUID.randomUUID());
					String observableType = "DNS Record";
					Set<Object> description = new HashSet<Object>();
					String d = GraphUtils.buildString("Requested domain name ", dnsName, " resolved to IP address ", reqIp);
					description.add(d); 
					String sourceDocument = TemplatesUtils.setDNSRecordObservable(dnsRecordID, "DNSRecord", d, record.get(LAST_SEEN_TIMET), dnsNameID, reqIpID, 
						record.get(RQTYPE), record.get(TTL), record.get(FLAGS), srcIpID, dstIpID);
					JSONObject dnsRecordJson = GraphUtils.setObservableJson(dnsRecordName, observableType, sourceDocument, description, source);
					vertices.put(dnsRecordID, dnsRecordJson);
					vertNames.put(dnsRecordName, dnsRecordID);
					/* dnsRecord -> dnsName edge */
					JSONObject edge = GraphUtils.setEdgeJson(dnsRecordID, "Observable", dnsNameID, "Observable", "Sub-Observable");
					edges.put(edge);
					/* dnsRecord -> requested ip edge */
					edge = GraphUtils.setEdgeJson(dnsRecordID, "Observable", reqIpID, "IP", "Sub-Observable");
					edges.put(edge);
				}

				/* dnsRecord -> srcIP */
				if (srcIpID != null) {
					String edgeName = GraphUtils.buildString(dnsRecordID, srcIpID);
					if (!edgeNames.contains(edgeName)) {
						JSONObject edge = GraphUtils.setEdgeJson(dnsRecordID, "Observable", srcIpID, "IP", "Sub-Observable");
						edges.put(edge);
						edgeNames.add(edgeName);
					}
				}
				/* dnsRecord -> dstIP */
				if (dstIpID != null) {
					String edgeName = GraphUtils.buildString(dnsRecordID, dstIpID);
					if (!edgeNames.contains(edgeName)) {
						JSONObject edge = GraphUtils.setEdgeJson(dnsRecordID, "Observable", dstIpID, "IP", "Sub-Observable");
						edges.put(edge);
						edgeNames.add(edgeName);
					}	
				}
			} catch (RuntimeException e) {
				e.printStackTrace();
			}
		}

		return (vertices.length() == 0) ? null : graph;
	}
}