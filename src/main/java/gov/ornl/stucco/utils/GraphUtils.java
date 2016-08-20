package gov.ornl.stucco.utils;

import java.util.Set;
import java.util.HashSet;
import java.util.UUID;

import org.json.JSONObject;
 
import org.apache.commons.csv.CSVRecord;

public abstract class GraphUtils {

	public static JSONObject setIpJson(String ip, String ipID, Object sourceSet, String sourceString) {
	  JSONObject ipJson = new JSONObject();
		ipJson.put("vertexType", "IP");
		ipJson.put("name", ip);
		Set<String> description = new HashSet<String>();
		description.add(ip);
		ipJson.put("description", (Object)description);
		ipJson.put("ipInt", ExtractorUtils.ipToLong(ip));
		ipJson.put("source", (Object)sourceSet);
		ipJson.put("observableType", "Address");
		String ipObservable = TemplatesUtils.setIPObservable(ip, ipID, sourceString);
		ipJson.put("sourceDocument", ipObservable);

		return ipJson;
	}

	public static JSONObject setPortJson(String port, Object sourceSet, String sourceString) {
		JSONObject portJson = new JSONObject();
		portJson.put("vertexType", "Observable");
		portJson.put("name", port);
		Set<String> description = new HashSet<String>();
		description.add(port);
		portJson.put("description", (Object)description);
		portJson.put("source", (Object)sourceSet);
		portJson.put("observableType", "Port");
		String uuid = UUID.randomUUID().toString();
		String portObservable = TemplatesUtils.setPortObservable(port, uuid, sourceString);
		portJson.put("sourceDocument", portObservable);

		return portJson;
	}

	public static JSONObject setAddressJson(String ip, String ipID, String port, String portID, Set sourceSet, String sourceString) {
		JSONObject addressJson = new JSONObject();
		addressJson.put("vertexType", "Observable");
		addressJson.put("name", buildString(ip, ":", port));
		Set<String> description = new HashSet<String>();
		description.add(buildString(ip, ", port ", port));
		addressJson.put("description", (Object)description);
		addressJson.put("source", (Object)sourceSet);
		addressJson.put("observableType", "Socket Address");
		String uuid = UUID.randomUUID().toString();
		String addressObservable = TemplatesUtils.setAddressObservable(uuid, ip, ipID, port, portID, sourceString);
		addressJson.put("sourceDocument", addressObservable);

    return addressJson;
	}

	public static JSONObject setFlowJson(String flowID, String srcIp, String srcPort, String srcAddressID, String dstIp, String dstPort, String dstAddressID, String protocol, Set sourceSet, String sourceString, Set<String> headersSet, CSVRecord record) {
		String flowObservable = TemplatesUtils.setFlowObservable(flowID, srcIp, srcPort, srcAddressID, dstIp, dstPort, dstAddressID, protocol, sourceString, headersSet, record);

		return setFlowObservable(flowID, srcIp, srcPort, srcAddressID, dstIp, dstPort, dstAddressID, protocol, sourceSet, sourceString, flowObservable);
	}

	public static JSONObject setFlowJson(String flowID, String srcIp, String srcPort, String srcAddressID, String dstIp, String dstPort, String dstAddressID, String protocol, Set sourceSet, String sourceString, JSONObject json) {
		String flowObservable = TemplatesUtils.setFlowObservable(flowID, srcIp, srcPort, srcAddressID, dstIp, dstPort, dstAddressID, protocol, sourceString, json);
		
		return setFlowObservable(flowID, srcIp, srcPort, srcAddressID, dstIp, dstPort, dstAddressID, protocol, sourceSet, sourceString, flowObservable);
	}

	private static JSONObject setFlowObservable(String flowID, String srcIp, String srcPort, String srcAddressID, String dstIp, String dstPort, String dstAddressID, String protocol, Set sourceSet, String sourceString, String sourceDocument) {
		JSONObject flowJson = new JSONObject();
		flowJson.put("vertexType", "Observable");
		flowJson.put("name", buildString(srcIp, ":", srcPort, "_through_", dstIp, ":", dstPort));
		Set<String> description = new HashSet<String>();
		description.add(buildString(srcIp, ", port ", srcPort, " to ", dstIp, ", port ", dstPort));
		flowJson.put("description", (Object)description);
		flowJson.put("source", (Object)sourceSet);
		flowJson.put("observableType", "Network Flow");
		flowJson.put("sourceDocument", sourceDocument);

		return flowJson;
	}

	public static JSONObject setDNSNameJson(String dnsID, String dnsName, String dnsIpID, Set sourceSet, String sourceString) {
		JSONObject dnsNameJson = new JSONObject();
		dnsNameJson.put("vertexType", "Observable");
		dnsNameJson.put("name", dnsName);
		Set<String> description = new HashSet<String>();
		description.add(buildString(dnsName));
		dnsNameJson.put("description", (Object)description);
		dnsNameJson.put("source", (Object)sourceSet);
		dnsNameJson.put("observableType", "Domain Name");
		String dnsNameObservable = TemplatesUtils.setDNSNameObservable(dnsID, dnsName, dnsIpID, sourceString);
		dnsNameJson.put("sourceDocument", dnsNameObservable);

		return dnsNameJson;
	}

	public static JSONObject setURIJson(String uriID, String uri, Set sourceSet) {
		JSONObject uriJson = new JSONObject();
		uriJson.put("vertexType", "Observable");
		uriJson.put("name", uri);
		Set<String> description = new HashSet<String>();
		description.add(buildString(uri));
		uriJson.put("description", (Object)description);
		uriJson.put("source", (Object)sourceSet);
		uriJson.put("observableType", "URI");
		String uriObservable = TemplatesUtils.setURIObservable(uriID, uri);
		uriJson.put("sourceDocument", uriObservable);

		return uriJson;
	}

	public static JSONObject setHTTPSessionJson(String httpID, Set sourceSet, String sourceString, String requestedURL, String ... props) {
		JSONObject httpSessionJson = new JSONObject();
		httpSessionJson.put("vertexType", "Observable");
		httpSessionJson.put("name", requestedURL);
		Set<String> description = new HashSet<String>();
		description.add(buildString("HTTP request of ", requestedURL));
		httpSessionJson.put("description", (Object)description);
		httpSessionJson.put("source", (Object)sourceSet);
		httpSessionJson.put("observableType", "HTTP Session");
		// httpSessionID, sourceString, requestedURL, method, ampVersion, rawHeader, language, length, date, ipID, dnsNameID, portID, uriID, agent
		String httpSessionObservable = TemplatesUtils.setHTTPSessionObservable(httpID, sourceString, requestedURL, props);
		httpSessionJson.put("sourceDocument", httpSessionObservable);

		return httpSessionJson;
	}

	public static JSONObject setEdgeJson(String outVertID, String outVertTable, String inVertID, String inVertTable, String relation) {
		JSONObject edge = new JSONObject();
		edge.put("outVertID", outVertID);
		edge.put("outVertTable", outVertTable);
		edge.put("inVertID", inVertID);
		edge.put("inVertTable", inVertTable);
		edge.put("relation", relation);

		return edge;
	}

	/**
	* concatenates multiple substrings 
	*/
  public static String buildString(Object... substrings) {
      StringBuilder str = new StringBuilder();
      for (Object substring : substrings) {
          str.append(substring);
      }

      return str.toString();
  }
}