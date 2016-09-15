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
 
import java.io.IOException;
 
import org.apache.commons.csv.CSVRecord;
 
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.json.JSONObject;
import org.json.JSONArray;
 
/**
 * Banner data to STIX format extractor.
 *
 * @author Maria Vincent
 */
public class BannerGraphExtractor {

	private static final Logger logger = LoggerFactory.getLogger(BannerGraphExtractor.class);
	private static String[] HEADERS = {"filename","recnum","file_type","amp_version","site","banner","addr","app_protocol","times_seen",
					   "first_seen","last_seen","cc","org","lat","lon"};
	private static final String FILENAME = "filename";
	private static final String ADDR = "addr";
	private static final String APP_PROTOCOL = "app_protocol";
	private static final String BANNER = "banner";	

	private JSONObject graph = null;
	
	public BannerGraphExtractor(String bannerInfo) {
		graph = extract(bannerInfo);
	}
					
	public JSONObject getGraph() {
		return graph;
	}

	private JSONObject extract (String bannerInfo) {
		List<CSVRecord> records;
		try {
			records = ExtractorUtils.getCSVRecordsList(HEADERS, bannerInfo);
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
		Set<Object> source = new HashSet<Object>();
		source.add("Banner");
	 	
		for (int i = start; i < records.size(); i++) {
			
			record = records.get(i);
			if (record.get(ADDR).isEmpty() || record.get(APP_PROTOCOL).isEmpty()) {
				continue;
			}
			
			String ipID = null;
			String portID = null;
			String addressID = null;

			String ip = null;
			String port = null;
			String address = null;

			/* ip */
			ip = record.get(ADDR);
			if (vertNames.containsKey(ip)) {
				ipID = vertNames.get(ip);
			} else {
				ipID = GraphUtils.buildString("stucco:Observable-", UUID.randomUUID());
				JSONObject ipJson = GraphUtils.setIpJson(ipID, ip, source, "Banner");
				vertices.put(ipID, ipJson);
				vertNames.put(ip, ipID);
			}
 
			/* port */
			port = record.get(APP_PROTOCOL);
			if (vertNames.containsKey(port)) {
				portID = vertNames.get(port);
			} else {
				portID = GraphUtils.buildString("stucco:Observable-", UUID.randomUUID());
				JSONObject portJson = GraphUtils.setPortJson(portID, port, source, "Banner");
				vertices.put(portID, portJson);
				vertNames.put(port, portID);
			}

			/* address */
			address = GraphUtils.buildString(ip, ":", port);
			if (vertNames.containsKey(address)) {
				addressID = vertNames.get(address);
			} else {
				addressID = GraphUtils.buildString("stucco:Observable-", UUID.randomUUID());
				Set<Object> description = new HashSet<Object>();
				String d = GraphUtils.buildString(ip,", port ", port);
				description.add(d);
				String banner = record.get(BANNER);
				String sourceDocument = TemplatesUtils.setBannerAddressObservable(addressID, "Banner", d, banner, ipID, portID);
				JSONObject addressJson = GraphUtils.setObservableJson(address, "Socket Address", sourceDocument, description, source);
				vertices.put(addressID, addressJson);
				vertNames.put(address, addressID);
				/* source address -> ip edge */
				JSONObject edge = GraphUtils.setEdgeJson(addressID,  "Observable", ipID, "IP", "Sub-Observable");
				edges.put(edge);
				/* source address -> port edge */
				edge = GraphUtils.setEdgeJson(addressID, "Observable", portID, "Observable", "Sub-Observable");
				edges.put(edge);
			}
		}

		return (vertices.length() == 0) ? null : graph;
	}
}