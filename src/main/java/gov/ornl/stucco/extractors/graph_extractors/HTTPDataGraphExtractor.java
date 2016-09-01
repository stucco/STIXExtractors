package gov.ornl.stucco.graph_extractors;

import gov.ornl.stucco.utils.ExtractorUtils;
import gov.ornl.stucco.utils.GraphUtils;

import java.util.List;
import java.util.UUID;
import java.util.Map;
import java.util.HashMap;
import java.util.Set;
import java.util.HashSet;

import java.io.IOException;

import org.apache.commons.csv.CSVRecord;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory; 

import org.json.JSONObject;
import org.json.JSONArray;

/**
 * CPP HTTP data to Graph format extractor. 
 *
 * @author Maria Vincent
 */
public class HTTPDataGraphExtractor {
						
	private static final Logger logger = LoggerFactory.getLogger(HTTPDataGraphExtractor.class);
	private static String[] HEADERS = {"filename", "recnum", "file_type", "amp_version", "site", "saddr", "daddr", "request_len", "dport", "times_seen", "first_seen_timet",	
					"last_seen_timet", "method", "request", "query_terms", "accept_language", "user_agent", "server_fqdn", "referer", "uri", "clean_data", 
					"full_data", "scountrycode", "sorganization", "slat", "slong", "dcountrycode", "dorganization", "dlat", "dlong", "distance"}; 
	static final String FILENAME = "filename";
	static final String AMP_VERSION = "amp_version";
	static final String SADDR = "saddr";
	static final String REQUEST_LEN = "request_len";
	static final String DPORT = "dport";
	static final String LAST_SEEN_TIMET = "last_seen_timet";
	static final String METHOD = "method";
	static final String REQUEST = "request";
	static final String ACCEPT_LANGUAGE = "accept_language";
	static final String USER_AGENT = "user_agent";
	static final String SERVER_FQDN = "server_fqdn";
	static final String REFERER = "referer";
	static final String FULL_DATA = "full_data";
	static final String DADDR = "daddr";		
	
	private JSONObject graph;
	
	public HTTPDataGraphExtractor(String httpInfo) {
		graph = extract(httpInfo);
	}
					
	public JSONObject getGraph() {
		return graph;
	}

	private JSONObject extract (String httpInfo) {
		List<CSVRecord> records;
		try {
			records = ExtractorUtils.getCSVRecordsList(HEADERS, httpInfo);
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
		/* mapping vert name to vert id to detect vert duplicates */
		Map<String, String> vertNames = new HashMap<String, String>();
		/* keep truck of edges to detect duplicates */
		Set<String> edgeNames = new HashSet<String>();
		Set<String> source = new HashSet<String>();
		source.add("HTTPRequest");

		for (int i = start; i < records.size(); i++) {
			record = records.get(i);

			if (record.get(SADDR).isEmpty() && record.get(DADDR).isEmpty() && record.get(SERVER_FQDN).isEmpty() && record.get(REQUEST).isEmpty()) {
				continue;
			}

			String srcIp = null;
			String dstIp = null;
			String dstPort = null;
			String dnsName = null;
			String uri = null;
			String fullData = null;
			String referer = null;

			String srcIpID = null;
			String dstIpID = null;
			String dstPortID = null;
			String dnsNameID = null;
			String uriID = null;
			String httpSessionID = null;
			String refererID = null;
		
			/* source ip vert */
			if (!record.get(SADDR).isEmpty()) {
				srcIp = record.get(SADDR);
				if (vertNames.containsKey(srcIp)) {
					srcIpID = vertNames.get(srcIp);
				} else {
					srcIpID = GraphUtils.buildString("stucco:Observable-", UUID.randomUUID());
					JSONObject srcIpJson = GraphUtils.setIpJson(srcIpID, srcIp, source, "HTTPRequest");
					vertices.put(srcIpID, srcIpJson);
					vertNames.put(srcIp, srcIpID);
				}
			}

			/* destination ip vert */
			if (!record.get(DADDR).isEmpty()) {
				dstIp = record.get(DADDR);
				if (vertNames.containsKey(dstIp)) {
					dstIpID = vertNames.get(dstIp);
				} else {
					dstIpID = GraphUtils.buildString("stucco:Observable-", UUID.randomUUID());
					JSONObject dstIpJson = GraphUtils.setIpJson(dstIpID, dstIp, source, "HTTPRequest");
					vertices.put(dstIpID, dstIpJson);
					vertNames.put(dstIpID, dstIp);
				}
			}

			/* destination port vert */
			if (!record.get(DPORT).isEmpty()) {
				dstPort = record.get(DPORT);
				if (vertNames.containsKey(dstPort)) {
					dstPortID = vertNames.get(dstPort);
				} else {
					dstPortID = GraphUtils.buildString("stucco:Observable-", UUID.randomUUID());
					JSONObject dstPortJson = GraphUtils.setPortJson(dstPortID, dstPort, source, "HTTPRequest");
					vertices.put(dstPortID, dstPortJson);
					vertNames.put(dstPort, dstPortID);
				}
			}

			/* server domain name vert */
			if (!record.get(SERVER_FQDN).isEmpty()) {
				dnsName = record.get(SERVER_FQDN);
				if (vertNames.containsKey(dnsName)) {
					dnsNameID = vertNames.get(dnsName);
				} else {
					dnsNameID = GraphUtils.buildString("stucco:Observable-", UUID.randomUUID());
					JSONObject dnsNameJson = GraphUtils.setDNSNameJson(dnsNameID, dnsName, dstIpID, source, "HTTPRequest");
					vertices.put(dnsNameID, dnsNameJson);
					vertNames.put(dnsName, dnsNameID);
				}
				/* server domain name -> ip address edge */
				String edgeName = GraphUtils.buildString(dnsNameID, dstIpID);
				boolean newEdge = !edgeNames.contains(edgeName);
				if (newEdge) {
					JSONObject edge = GraphUtils.setEdgeJson(dnsNameID,  "Observable", dstIpID, "IP", "Sub-Observable");
					edges.put(edge);
					edgeNames.add(edgeName);
				}
			}

			/* requested uri vertex */
			if (!record.get(REQUEST).isEmpty()) {
				uri = record.get(REQUEST);
				if (vertNames.containsKey(uri)) {
					uriID = vertNames.get(uri);
				} else {
					uriID =  GraphUtils.buildString("stucco:Observable-", UUID.randomUUID());
					JSONObject uriJson = GraphUtils.setURIJson(uriID, uri, source);
					vertices.put(uriID, uriJson);
					vertNames.put(uri, uriID);
				}
			}

			/* requested uri vertex */
			if (!record.get(REFERER).isEmpty()) {
				referer = record.get(REFERER);
				if (vertNames.containsKey(referer)) {
					refererID = vertNames.get(referer);
				} else {
					refererID =  GraphUtils.buildString("stucco:Observable-", UUID.randomUUID());
					JSONObject uriJson = GraphUtils.setURIJson(refererID, referer, source);
					vertices.put(refererID, uriJson);
					vertNames.put(referer, refererID);
				}
			}

			/* http session vertex */
			if (!record.get(FULL_DATA).isEmpty()) {
				fullData = record.get(FULL_DATA);
				if (vertNames.containsKey(fullData)) {
					httpSessionID = vertNames.get(fullData);
				} else {
					httpSessionID = GraphUtils.buildString("stucco:Observable-", UUID.randomUUID());
					String sourceDocument = setHTTPSessionObservable(httpSessionID, record, srcIpID, dnsNameID, dstPortID, uriID, refererID);
					JSONObject httpSessionJson = GraphUtils.setHTTPSessionJson(httpSessionID, source, "HTTPRequest", fullData, sourceDocument);



					vertices.put(httpSessionID, httpSessionJson);
					vertNames.put(fullData, httpSessionID);
				}
				/* http session -> source ip edge */
				String edgeName = GraphUtils.buildString(httpSessionID, srcIpID);
				boolean newEdge = !edgeNames.contains(edgeName);
				if (newEdge) {
					JSONObject edge = GraphUtils.setEdgeJson(httpSessionID, "Observable", srcIpID, "IP", "Sub-Observable");
					edges.put(edge);
					edgeNames.add(edgeName);
				}
				/* http session -> server domain name edge */
				edgeName = GraphUtils.buildString(httpSessionID, dnsNameID);
				newEdge =  !edgeNames.contains(edgeName);
				if (newEdge) {
					JSONObject edge = GraphUtils.setEdgeJson(httpSessionID, "Observable", dnsNameID, "Observable", "Sub-Observable");
					edges.put(edge);
					edgeNames.add(edgeName);
				}
				/* http session -> server port edge */
				edgeName = GraphUtils.buildString(httpSessionID, dstPortID);
				newEdge = !edgeNames.contains(edgeName);
				if (newEdge) {
					JSONObject edge = GraphUtils.setEdgeJson(httpSessionID, "Observable", dstPortID, "Observable", "Sub-Observable");
					edges.put(edge);
					edgeNames.add(edgeName);
				}
				/* http session -> requested uri edge */
				edgeName = GraphUtils.buildString(httpSessionID, uriID);
				newEdge =  !edgeNames.contains(edgeName);
				if (newEdge) {
					JSONObject edge = GraphUtils.setEdgeJson(httpSessionID, "Observable", uriID, "Observable", "Sub-Observable");
					edges.put(edge);
					edgeNames.add(edgeName);
				}

				/* http session -> referer uri edge */
				edgeName = GraphUtils.buildString(httpSessionID, refererID);
				newEdge =  !edgeNames.contains(edgeName);
				if (newEdge) {
					JSONObject edge = GraphUtils.setEdgeJson(httpSessionID, "Observable", refererID, "Observable", "Sub-Observable");
					edges.put(edge);
					edgeNames.add(edgeName);
				}
			}
		}

		return (edges.length() == 0 && vertices.length() == 0) ? null : graph;		
	}

	private static String setHTTPSessionObservable(String httpSessionID, CSVRecord record, String srcIpID, String dnsNameID, String dstPortID, String uriID, String refererID) {
		String host = GraphUtils.buildString(
			(dnsNameID == null) ? "" : GraphUtils.buildString("<HTTPSessionObj:Domain_Name object_reference=\"", dnsNameID, "\" />"),
			(dstPortID == null) ? "" : GraphUtils.buildString("<HTTPSessionObj:Port object_reference=\"", dstPortID, "\" />")
		);
		String rawHeader = GraphUtils.buildString(
			"<HTTPSessionObj:Raw_Header>", record.get(FULL_DATA), "</HTTPSessionObj:Raw_Header>"
		);
		String parsedHeader = GraphUtils.buildString(
			"<HTTPSessionObj:Parsed_Header>",
			(record.get(ACCEPT_LANGUAGE).isEmpty()) ? "" : GraphUtils.buildString("<HTTPSessionObj:Accept_Language>", record.get(ACCEPT_LANGUAGE), "</HTTPSessionObj:Accept_Language>"),
			(record.get(REQUEST_LEN).isEmpty()) ? "" : GraphUtils.buildString("<HTTPSessionObj:Content_Length>", record.get(REQUEST_LEN), "</HTTPSessionObj:Content_Length>"),
			(record.get(LAST_SEEN_TIMET).isEmpty()) ? "" : GraphUtils.buildString("<HTTPSessionObj:Date>", record.get(LAST_SEEN_TIMET), "</HTTPSessionObj:Date>"),
			(srcIpID == null) ? "" : GraphUtils.buildString("<HTTPSessionObj:From object_reference=\"", srcIpID,"\" />"),
			(host.isEmpty()) ? "" : GraphUtils.buildString("<HTTPSessionObj:Host>", host, "</HTTPSessionObj:Host>"),
			(refererID == null) ? "" : GraphUtils.buildString("<HTTPSessionObj:Referer idref=\"", refererID, "\" />"),
			(record.get(USER_AGENT).isEmpty()) ? "" : GraphUtils.buildString("<HTTPSessionObj:User_Agent>", record.get(USER_AGENT), "</HTTPSessionObj:User_Agent>"),
			"</HTTPSessionObj:Parsed_Header>"
		);
		String httpRequestHeader = GraphUtils.buildString(
				"<HTTPSessionObj:HTTP_Request_Header>",
				rawHeader,
				parsedHeader,
				"</HTTPSessionObj:HTTP_Request_Header>"
		);

		String httpSessionObservable = GraphUtils.buildString("<cybox:Observable xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" xmlns:stucco=\"gov.ornl.stucco\" id=\"",
			httpSessionID,
			"\"><cybox:Title>HTTPRequest</cybox:Title><cybox:Observable_Source><cyboxCommon:Information_Source_Type xmlns:cyboxCommon=\"http://cybox.mitre.org/common-2\">",
			"HTTPRequest",
			"</cyboxCommon:Information_Source_Type></cybox:Observable_Source><cybox:Object><cybox:Description>HTTP request: ",
			record.get(REQUEST),
			"</cybox:Description><cybox:Properties xmlns:HTTPSessionObj=\"http://cybox.mitre.org/objects#HTTPSessionObject-2\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"HTTPSessionObj:HTTPSessionObjectType\"><HTTPSessionObj:HTTP_Request_Response><HTTPSessionObj:HTTP_Client_Request><HTTPSessionObj:HTTP_Request_Line>",
			(record.get(METHOD).isEmpty()) ? "" : GraphUtils.buildString("<HTTPSessionObj:HTTP_Method>", record.get(METHOD), "</HTTPSessionObj:HTTP_Method>"),
			"<HTTPSessionObj:Value idref=\"",
			uriID,
			"\" >",
			(record.get(AMP_VERSION).isEmpty()) ? "" : GraphUtils.buildString("<HTTPSessionObj:Version>", record.get(AMP_VERSION),"</HTTPSessionObj:Version>"),
			"</HTTPSessionObj:HTTP_Request_Line>",
			httpRequestHeader,
			"</HTTPSessionObj:HTTP_Client_Request></HTTPSessionObj:HTTP_Request_Response></cybox:Properties></cybox:Object></cybox:Observable>"
		);

		return httpSessionObservable;
	}
}
