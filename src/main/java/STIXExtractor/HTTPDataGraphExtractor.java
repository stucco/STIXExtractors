package STIXExtractor;

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
public class HTTPDataGraphExtractor extends STIXExtractor {
						
	private static final Logger logger = LoggerFactory.getLogger(ServiceListExtractor.class);
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
	private JSONObject vertices;
	private JSONArray edges;
	
	public HTTPDataGraphExtractor(String httpInfo) {
		graph = extract(httpInfo);
	}
					
	public JSONObject getGraph() {
		return graph;
	}

	private JSONObject extract (String httpInfo) {
		List<CSVRecord> records;
		try {
			records = getCSVRecordsList(HEADERS, httpInfo);
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

		vertices = new JSONObject();
		edges = new JSONArray();
		graph = new JSONObject();
		graph.put("vertices", vertices);
		graph.put("edges", edges);
		Map<String, String> vertNames = new HashMap<String, String>();
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
			String httpSession = null;
			String uri = null;
			String request = null;

			String srcIpID = null;
			String dstIpID = null;
			String dstPortID = null;
			String dnsNameID = null;
			String uriID = null;
			String httpSessionID = null;

			JSONObject srcIpJson = null;
			JSONObject dstIpJson = null;
			JSONObject dstPortJson = null;
			JSONObject dnsNameJson = null;
			JSONObject uriJson = null;
			JSONObject httpSessionJson = null;
		
			if (!record.get(SADDR).isEmpty()) {
				srcIp = record.get(SADDR);
				if (vertNames.containsKey(srcIp)) {
					srcIpID = vertNames.get(srcIp);
				} else {
					srcIpID = UUID.randomUUID().toString();
					srcIpJson = GraphUtils.setIpJson(srcIp, srcIpID, source, "HTTPRequest");
					vertices.put(srcIpID, srcIpJson);
					vertNames.put(srcIp, srcIpID);
				}
			}

			if (!record.get(DADDR).isEmpty()) {
				dstIp = record.get(DADDR);
				if (vertNames.containsKey(dstIp)) {
					dstIpID = vertNames.get(dstIp);
				} else {
					dstIpID = UUID.randomUUID().toString();
					dstIpJson = GraphUtils.setIpJson(dstIp, dstIpID, source, "HTTPRequest");
					vertices.put(dstIpID, dstIpJson);
					vertNames.put(dstIpID, dstIp);
				}
			}

			if (!record.get(DPORT).isEmpty()) {
				dstPort = record.get(DPORT);
				if (vertNames.containsKey(dstPort)) {
					dstPortID = vertNames.get(dstPort);
				} else {
					dstPortID = UUID.randomUUID().toString();
					dstPortJson = GraphUtils.setPortJson(dstPort, source, "HTTPRequest");
					vertices.put(dstPortID, dstPortJson);
					vertNames.put(dstPort, dstPortID);
				}
			}

			if (!record.get(SERVER_FQDN).isEmpty()) {
				dnsName = record.get(SERVER_FQDN);
				if (vertNames.containsKey(dnsName)) {
					dnsNameID = vertNames.get(dnsName);
				} else {
					dnsNameID = UUID.randomUUID().toString();
					dnsNameJson = GraphUtils.setDNSNameJson(dnsNameID, dnsName, dstIpID, source, "HTTPRequest");
					vertices.put(dnsNameID, dnsNameJson);
					vertNames.put(dnsName, dnsNameID);
				}
				String edgeName = GraphUtils.buildString(dnsNameID, dstIpID);
				boolean newEdge = !edgeNames.contains(edgeName);
				if (newEdge) {
					JSONObject edge = GraphUtils.setEdgeJson(dnsNameID, dstIpID, "Sub-Observable");
					edges.put(edge);
					edgeNames.add(edgeName);
				}
			}

			if (!record.get(REFERER).isEmpty()) {
				uri = record.get(REFERER);
				if (vertNames.containsKey(uri)) {
					uriID = vertNames.get(uri);
				} else {
					uriID =  UUID.randomUUID().toString();
					uriJson = GraphUtils.setURIJson(uriID, uri, source);
					vertices.put(uriID, uriJson);
					vertNames.put(uri, uriID);
				}
			}

			if (!record.get(REQUEST).isEmpty()) {
				request = record.get(REQUEST);
				if (vertNames.containsKey(request)) {
					httpSessionID = vertNames.get(request);
				} else {
					httpSessionID = UUID.randomUUID().toString();
					httpSessionJson = GraphUtils.setHTTPSessionJson(
						httpSessionID,
						source, 
						"HTTPRequest", 
						request, 
						record.get(METHOD), 
						record.get(AMP_VERSION), 
						record.get(FULL_DATA), 
						record.get(ACCEPT_LANGUAGE), 
						record.get(REQUEST_LEN), 
						record.get(LAST_SEEN_TIMET), 
						srcIpID, 
						dnsNameID,
						dstPortID, 
						uriID, 
						record.get(USER_AGENT)
					);
					vertices.put(httpSessionID, httpSessionJson);
					vertNames.put(request, httpSessionID);
				}
				String edgeName = GraphUtils.buildString(httpSessionID, srcIpID);
				boolean newEdge = !edgeNames.contains(edgeName);
				if (newEdge) {
					JSONObject edge = GraphUtils.setEdgeJson(httpSessionID, srcIpID, "Sub-Observable");
					edges.put(edge);
					edgeNames.add(edgeName);
				}
				edgeName = GraphUtils.buildString(httpSessionID, dnsNameID);
				newEdge =  !edgeNames.contains(edgeName);
				if (newEdge) {
					JSONObject edge = GraphUtils.setEdgeJson(httpSessionID, dnsNameID, "Sub-Observable");
					edges.put(edge);
					edgeNames.add(edgeName);
				}
				edgeName = GraphUtils.buildString(httpSessionID, dstPortID);
				newEdge = !edgeNames.contains(edgeName);
				if (newEdge) {
					JSONObject edge = GraphUtils.setEdgeJson(httpSessionID, dstPortID, "Sub-Observable");
					edges.put(edge);
					edgeNames.add(edgeName);
				}
				edgeName = GraphUtils.buildString(httpSessionID, uriID);
				newEdge =  !edgeNames.contains(edgeName);
				if (newEdge) {
					JSONObject edge = GraphUtils.setEdgeJson(httpSessionID, uriID, "Sub-Observable");
					edges.put(edge);
					edgeNames.add(edgeName);
				}
			}
		}

		return (edges.length() == 0 && vertices.length() == 0) ? null : graph;		
	}
}
