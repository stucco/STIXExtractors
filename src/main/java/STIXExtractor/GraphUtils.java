package STIXExtractor;

import java.util.Set;
import java.util.HashSet;
import java.util.UUID;

import org.json.JSONObject;

import org.apache.commons.csv.CSVRecord;

public abstract class GraphUtils {

	static JSONObject setIpJson(String ip, String ipID, Set sourceSet, String sourceString) {
	  JSONObject ipJson = new JSONObject();
		ipJson.put("vertexType", "IP");
		ipJson.put("name", ip);
		Set<String> description = new HashSet<String>();
		description.add(ip);
		ipJson.put("description", description);
		ipJson.put("ipInt", ExtractorUtils.ipToLong(ip));
		ipJson.put("source", sourceSet);
		ipJson.put("observableType", "Address");
		String ipObservable = setIPObservable(ip, ipID, sourceString);
		ipJson.put("sourceDocument", ipObservable);

		return ipJson;
	}

	static JSONObject setPortJson(String port, Set sourceSet, String sourceString) {
		JSONObject portJson = new JSONObject();
		portJson.put("vertexType", "Observable");
		portJson.put("name", port);
		Set<String> description = new HashSet<String>();
		description.add(port);
		portJson.put("description", description);
		portJson.put("source", sourceSet);
		portJson.put("observableType", "Port");
		String uuid = UUID.randomUUID().toString();
		String portObservable = setPortObservable(port, uuid, sourceString);
		portJson.put("sourceDocument", portObservable);

		return portJson;
	}

	static JSONObject setAddressJson(String ip, String ipID, String port, String portID, Set sourceSet, String sourceString) {
		JSONObject addressJson = new JSONObject();
		addressJson.put("vertexType", "Observable");
		addressJson.put("name", buildString(ip, ":", port));
		Set<String> description = new HashSet<String>();
		description.add(buildString(ip, ", port ", port));
		addressJson.put("description", description);
		addressJson.put("source", sourceSet);
		addressJson.put("observableType", "Socket Address");
		String uuid = UUID.randomUUID().toString();
		String addressObservable = setAddressObservable(uuid, ip, ipID, port, portID, sourceString);
		addressJson.put("sourceDocument", addressObservable);

    return addressJson;
	}

	static JSONObject setFlowJson(String flowID, String srcIp, String srcPort, String srcAddressID, String dstIp, String dstPort, String dstAddressID, String protocol, Set sourceSet, String sourceString, Set<String> headersSet, CSVRecord record) {
		JSONObject flowJson = new JSONObject();
		flowJson.put("vertexType", "Observable");
		flowJson.put("name", buildString(srcIp, ":", srcPort, "_through_", dstIp, ":", dstPort));
		Set<String> description = new HashSet<String>();
		description.add(buildString(srcIp, ", port ", srcPort, " to ", dstIp, ", port ", dstPort));
		flowJson.put("description", description);
		flowJson.put("source", sourceSet);
		flowJson.put("observableType", "Network Flow");
		String flowObservable = setFlowObservable(flowID, srcIp, srcPort, srcAddressID, dstIp, dstPort, dstAddressID, protocol, sourceString, headersSet, record);
		flowJson.put("sourceDocument", flowObservable);

		return flowJson;
	}

	static JSONObject setEdgeJson(String outVertID, String outVertTable, String inVertID, String inVertTable, String relation) {
		JSONObject edge = new JSONObject();
		edge.put("outVertID", outVertID);
		edge.put("outVertTable", outVertTable);
		edge.put("inVertID", inVertID);
		edge.put("inVertTable", inVertTable);
		edge.put("relation", relation);

		return edge;
	}

	private static String setIPObservable(String ip, String ipID, String source) {
		String ipObservable = buildString("<cybox:Observable id=\"stucco:ip-", 
			ipID, 
			"\" xmlns:AddressObj=\"http://cybox.mitre.org/objects#AddressObject-2\" xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" xmlns:cyboxCommon=\"http://cybox.mitre.org/common-2\" xmlns:stucco=\"gov.ornl.stucco\"><cybox:Title>IP</cybox:Title><cybox:Observable_Source><cyboxCommon:Information_Source_Type>",
			source,
			"</cyboxCommon:Information_Source_Type></cybox:Observable_Source><cybox:Object><cybox:Description>",
    	ip, 
    	"</cybox:Description><cybox:Properties category=\"ipv4-addr\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"AddressObj:AddressObjectType\"><AddressObj:Address_Value>",
    	ip,
    	"</AddressObj:Address_Value></cybox:Properties></cybox:Object></cybox:Observable>"
    );
	
		return ipObservable;
	}

	private static String setPortObservable(String port, String portID, String source) {
		String portObservable = buildString("<cybox:Observable id=\"stucco:port-",
			portID,
			"\" xmlns:PortObj=\"http://cybox.mitre.org/objects#PortObject-2\" xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" xmlns:cyboxCommon=\"http://cybox.mitre.org/common-2\" xmlns:stucco=\"gov.ornl.stucco\"><cybox:Title>Port</cybox:Title><cybox:Observable_Source><cyboxCommon:Information_Source_Type>",
			source, 
			"</cyboxCommon:Information_Source_Type></cybox:Observable_Source><cybox:Object><cybox:Description>",
			port,
			"</cybox:Description><cybox:Properties xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"PortObj:PortObjectType\"><PortObj:Port_Value>22</PortObj:Port_Value></cybox:Properties></cybox:Object></cybox:Observable>"
		);

		return portObservable;
	}

	private static String setAddressObservable(String addressID, String ip, String ipID, String port, String portID, String source) {
		String addressObservable = buildString("<cybox:Observable id=\"stucco:address-",
			addressID, 
			"\" xmlns:SocketAddressObj=\"http://cybox.mitre.org/objects#SocketAddressObject-1\" xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" xmlns:cyboxCommon=\"http://cybox.mitre.org/common-2\" xmlns:stucco=\"gov.ornl.stucco\"><cybox:Title>Address</cybox:Title><cybox:Observable_Source><cyboxCommon:Information_Source_Type>",
			source,
			"</cyboxCommon:Information_Source_Type></cybox:Observable_Source><cybox:Object><cybox:Description>",
			ip, 
			", port ",
			port,
			"</cybox:Description><cybox:Properties xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"SocketAddressObj:SocketAddressObjectType\"><SocketAddressObj:IP_Address object_reference=\"stucco:ip-",
			ipID,
			"\"/><SocketAddressObj:Port object_reference=\"stucco:port-",
			portID,
			"\"/></cybox:Properties></cybox:Object></cybox:Observable>"
		);

		return addressObservable;
	}

	private static String setFlowObservable(String flowID, String srcIp, String srcPort, String srcAddressID, String dstIp, String dstPort, String dstAddressID, String protocol, String sourceString, Set<String> headersSet, CSVRecord record) {
		String customProperties = null;
		for (String header : headersSet) {
			if (!record.get(header).isEmpty()) {
				customProperties = buildString(customProperties, "<cyboxCommon:Property name=\"", header, "\">", record.get(header), "</cyboxCommon:Property>");
			}
		}
		if (customProperties != null) {
			customProperties = buildString("<cyboxCommon:Custom_Properties>", customProperties, "</cyboxCommon:Custom_Properties>");
		} 
		
		String flowObservable = buildString("<cybox:Observable id=\"stucco:flow-",
			flowID, 
			"\" xmlns:NetFlowObj=\"http://cybox.mitre.org/objects#NetworkFlowObject-2\" xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" xmlns:cyboxCommon=\"http://cybox.mitre.org/common-2\" xmlns:stucco=\"gov.ornl.stucco\"><cybox:Title>Flow</cybox:Title><cybox:Observable_Source><cyboxCommon:Information_Source_Type>",
			sourceString,
			"</cyboxCommon:Information_Source_Type></cybox:Observable_Source><cybox:Object><cybox:Description>",
			srcIp,
			", port ",
			srcPort,
			" to ",
			dstIp,
			", port ",
			dstPort,
			"</cybox:Description><cybox:Properties xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"NetFlowObj:NetworkFlowObjectType\">",
			customProperties,
			"<NetFlowObj:Network_Flow_Label><NetFlowObj:Src_Socket_Address object_reference=\"stucco:address-",
			srcAddressID,
			"\"/><NetFlowObj:Dest_Socket_Address object_reference=\"stucco:address-",
			dstAddressID,
			"\"/><NetFlowObj:IP_Protocol>",
			protocol,
			"</NetFlowObj:IP_Protocol></NetFlowObj:Network_Flow_Label></cybox:Properties></cybox:Object></cybox:Observable>"
		);

		return flowObservable;
	}

	/**
	* concatenates multiple substrings 
	*/
  static String buildString(Object... substrings) {
      StringBuilder str = new StringBuilder();
      for (Object substring : substrings) {
          str.append(substring);
      }

      return str.toString();
  }
}