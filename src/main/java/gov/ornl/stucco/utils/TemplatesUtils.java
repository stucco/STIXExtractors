package gov.ornl.stucco.utils;

import java.util.Collections;
import java.util.Set;
import java.util.HashSet;
import java.util.Map;
import java.util.HashMap;
import java.util.UUID;

import org.json.JSONObject;

import org.apache.commons.csv.CSVRecord;

import javax.xml.datatype.XMLGregorianCalendar;

public abstract class TemplatesUtils {
	private static final Map<String, String> situCustomProperties;

	static {
		Map<String, String> map = new HashMap<String, String>();
		map.put("score", "Situ_Anomaly_Score");
		map.put("malScore", "Situ_Maliciousness_Score");
		map.put("site", "CPP_Site");
		map.put("stime", "CPP_Time"); 
		map.put("duration", "CPP_Duration"); 
		map.put("sappbytes", "CPP_SrcAppBytes"); 
		map.put("dappbytes", "CPP_DstAppBytes");
		map.put("appbytes", "CPP_AppBytes"); 
		map.put("sbytes", "CPP_SrcBytes");
		map.put("dbytes", "CPP_DstBytes");
		map.put("bytes", "CPP_Bytes");
		map.put("spkts", "CPP_SrcPackets"); 
		map.put("dpkts", "CPP_DstPackets");
		map.put("pkts", "CPP_Packets");
		map.put("flgs", "CPP_Flags");
		situCustomProperties = Collections.unmodifiableMap(map);
	}

	protected static String setIPObservable(String ipID, String ip, String source) {
		String ipObservable = buildString("<cybox:Observable id=\"", 
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

	protected static String setPortObservable(String portID, String port, String source) {
		String portObservable = buildString("<cybox:Observable id=\"",
			portID,
			"\" xmlns:PortObj=\"http://cybox.mitre.org/objects#PortObject-2\" xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" xmlns:cyboxCommon=\"http://cybox.mitre.org/common-2\" xmlns:stucco=\"gov.ornl.stucco\"><cybox:Title>Port</cybox:Title><cybox:Observable_Source><cyboxCommon:Information_Source_Type>",
			source, 
			"</cyboxCommon:Information_Source_Type></cybox:Observable_Source><cybox:Object><cybox:Description>",
			port,
			"</cybox:Description><cybox:Properties xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"PortObj:PortObjectType\"><PortObj:Port_Value>",
			port,
			"</PortObj:Port_Value></cybox:Properties></cybox:Object></cybox:Observable>"
		);

		return portObservable;
	}

	protected static String setAddressObservable(String addressID, String ip, String ipID, String port, String portID, String source) {
		String addressObservable = buildString("<cybox:Observable id=\"",
			addressID, 
			"\" xmlns:SocketAddressObj=\"http://cybox.mitre.org/objects#SocketAddressObject-1\" xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" xmlns:cyboxCommon=\"http://cybox.mitre.org/common-2\" xmlns:stucco=\"gov.ornl.stucco\"><cybox:Title>Address</cybox:Title><cybox:Observable_Source><cyboxCommon:Information_Source_Type>",
			source,
			"</cyboxCommon:Information_Source_Type></cybox:Observable_Source><cybox:Object><cybox:Description>",
			ip, 
			", port ",
			port,
			"</cybox:Description><cybox:Properties xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"SocketAddressObj:SocketAddressObjectType\">",
			(ipID == null) ? null : buildString(
				"<SocketAddressObj:IP_Address object_reference=\"",
				ipID,
				"\"/>"
			),
			(portID == null) ? null : buildString(
				"<SocketAddressObj:Port object_reference=\"",
				portID,
				"\"/>"
			),
			"</cybox:Properties></cybox:Object></cybox:Observable>"
		);

		return addressObservable;
	}

	protected static String setFlowObservable(String flowID, String srcIp, String srcPort, String srcAddressID, String dstIp, String dstPort, String dstAddressID, String protocol, String sourceString, CSVRecord record, Set<String> headersSet) {
		String customProperties = buildCustomProperties(record, headersSet);

		return setFlowObservable(flowID, srcIp, srcPort, srcAddressID, dstIp, dstPort, dstAddressID, protocol, sourceString, customProperties);
	}

	protected static String setFlowObservable(String flowID, String srcIp, String srcPort, String srcAddressID, String dstIp, String dstPort, String dstAddressID, String protocol, String sourceString, CSVRecord record, String... customFields) {
		String customProperties = buildCustomProperties(record, customFields);

		return setFlowObservable(flowID, srcIp, srcPort, srcAddressID, dstIp, dstPort, dstAddressID, protocol, sourceString, customProperties);
	}

	// private static String buildCustomProperties(Set<String> headersSet, CSVRecord record) {
	private static String buildCustomProperties(CSVRecord record, Set<String> headersSet) {
		String customProperties = "";
		for (String header : headersSet) {
			if (!record.get(header).isEmpty()) {
				customProperties = buildString(customProperties, "<cyboxCommon:Property name=\"", header, "\">", record.get(header), "</cyboxCommon:Property>");
			}
		}

		return customProperties;
	}

	// private static String buildCustomProperties(Set<String> headersSet, CSVRecord record) {
	private static String buildCustomProperties(CSVRecord record, String... headersSet) {
		String customProperties = null;
		for (String header : headersSet) {
			if (!record.get(header).isEmpty()) {
				customProperties = buildString(customProperties, "<cyboxCommon:Property name=\"", header, "\">", record.get(header), "</cyboxCommon:Property>");
			}
		}

		return customProperties;
	}

	protected static String setFlowObservable(String flowID, String srcIp, String srcPort, String srcAddressID, String dstIp, String dstPort, String dstAddressID, String protocol, String sourceString, JSONObject json) {
		String customProperties = buildCustomProperties(json);
		
		return setFlowObservable(flowID, srcIp, srcPort, srcAddressID, dstIp, dstPort, dstAddressID, protocol, sourceString, customProperties);
	}

	private static String buildCustomProperties(JSONObject json) {
		String customProperties = null;
		for (String key : situCustomProperties.keySet()) {
			if (json.has(key)) {
				customProperties = buildString(customProperties, "<cyboxCommon:Property name=\"", situCustomProperties.get(key), "\">", json.get(key), "</cyboxCommon:Property>");	
			}
		}
		
		return customProperties;
	}
	private static String setFlowObservable(String flowID, String srcIp, String srcPort, String srcAddressID, String dstIp, String dstPort, String dstAddressID, String protocol, String sourceString, String customProperties) {
		String networkFlow = buildString(
			(srcAddressID == null) ? null : buildString("<NetFlowObj:Src_Socket_Address object_reference=\"", srcAddressID, "\"/>"),
			(dstAddressID == null) ? null : buildString("<NetFlowObj:Dest_Socket_Address object_reference=\"", dstAddressID, "\"/>"),
			(protocol == null) ? null : buildString("<NetFlowObj:IP_Protocol>", protocol, "</NetFlowObj:IP_Protocol>")
		);

		String networkFlowLabel = buildString(
			(networkFlow.isEmpty()) ? null : buildString("<NetFlowObj:Network_Flow_Label>", networkFlow, "</NetFlowObj:Network_Flow_Label>")
		);
		
		String flowObservable = buildString(
			"<cybox:Observable id=\"",
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
			(customProperties.isEmpty()) ? null : buildString("<cyboxCommon:Custom_Properties>", customProperties, "</cyboxCommon:Custom_Properties>"),
			networkFlowLabel,
			"</cybox:Properties></cybox:Object></cybox:Observable>"
		);

		return flowObservable;
	}

	protected static String setDNSNameObservable(String dnsID, String dnsName, String dnsIpID, String sourceString) {
		String relatedObject = (dnsIpID == null) ? null : buildString(
			"<cybox:Related_Objects><cybox:Related_Object idref=\"", dnsIpID, "\"></cybox:Related_Object></cybox:Related_Objects>"
		);
		String dnsObservable = buildString("<cybox:Observable xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" xmlns:stucco=\"gov.ornl.stucco\" id=\"",
			dnsID,
			"\"><cybox:Title>DNSName</cybox:Title><cybox:Observable_Source><cyboxCommon:Information_Source_Type xmlns:cyboxCommon=\"http://cybox.mitre.org/common-2\">",
			sourceString,
			"</cyboxCommon:Information_Source_Type></cybox:Observable_Source><cybox:Object><cybox:Description>",
			dnsName,
			"</cybox:Description><cybox:Properties xmlns:DomainNameObj=\"http://cybox.mitre.org/objects#DomainNameObject-1\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"DomainNameObj:DomainNameObjectType\"><DomainNameObj:Value>",
			dnsName,
			"</DomainNameObj:Value></cybox:Properties>",
			relatedObject,
			"</cybox:Object></cybox:Observable>"
		);

		return dnsObservable;
	}

	//private static String setHTTPSessionObservable(String httpSessionID, String sourceString, String requestedURL, String method, String ampVersion, String rawHeader, String language, String length, String date, String ipID, String dnsNameID, String portID, String uriID, String agent) {
	protected static String setHTTPSessionObservable(String httpSessionID, String sourceString, String requestedURL, String... props) {
		String host = buildString(
			(props[7] == null) ? null : buildString("<HTTPSessionObj:Domain_Name object_reference=\"", props[7], "\" />"),
			(props[8] == null) ? null : buildString("<HTTPSessionObj:Port object_reference=\"", props[8], "\" />")
		);
		String rawHeader = buildString(
			"<HTTPSessionObj:Raw_Header>", props[2], "</HTTPSessionObj:Raw_Header>"
		);
		String parsedHeader = buildString(
			"<HTTPSessionObj:Parsed_Header>",
			(props[3] == null) ? null : buildString("<HTTPSessionObj:Accept_Language>", props[3], "</HTTPSessionObj:Accept_Language>"),
			(props[4] == null) ? null : buildString("<HTTPSessionObj:Content_Length>", props[4], "</HTTPSessionObj:Content_Length>"),
			(props[5] == null) ? null : buildString("<HTTPSessionObj:Date>", props[5], "</HTTPSessionObj:Date>"),
			(props[6] == null) ? null : buildString("<HTTPSessionObj:From object_reference=\"", props[6],"\" />"),
			(host == null) ? null : buildString("<HTTPSessionObj:Host>", host, "</HTTPSessionObj:Host>"),
			(props[9] == null) ? null : buildString("<HTTPSessionObj:Referer object_reference=\"", props[9], "\" />"),
			(props[10] == null) ? null : buildString("<HTTPSessionObj:User_Agent>", props[10], "</HTTPSessionObj:User_Agent>"),
			"</HTTPSessionObj:Parsed_Header>"
		);
		String httpRequestHeader = buildString(
			(rawHeader == null && parsedHeader == null) ? null : buildString(
				"<HTTPSessionObj:HTTP_Request_Header>",
				rawHeader,
				parsedHeader,
				"</HTTPSessionObj:HTTP_Request_Header>"
			)
		);

		String httpSessionObservable = buildString("<cybox:Observable xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" xmlns:stucco=\"gov.ornl.stucco\" id=\"",
			httpSessionID,
			"\"><cybox:Title>HTTPRequest</cybox:Title><cybox:Observable_Source><cyboxCommon:Information_Source_Type xmlns:cyboxCommon=\"http://cybox.mitre.org/common-2\">",
			sourceString,
			"</cyboxCommon:Information_Source_Type></cybox:Observable_Source><cybox:Object><cybox:Description>HTTP request of ",
			requestedURL,
			"</cybox:Description><cybox:Properties xmlns:HTTPSessionObj=\"http://cybox.mitre.org/objects#HTTPSessionObject-2\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"HTTPSessionObj:HTTPSessionObjectType\"><HTTPSessionObj:HTTP_Request_Response><HTTPSessionObj:HTTP_Client_Request><HTTPSessionObj:HTTP_Request_Line>",
			(props[0] == null) ? null : buildString("<HTTPSessionObj:HTTP_Method>", props[0], "</HTTPSessionObj:HTTP_Method>"),
			"<HTTPSessionObj:Value>",
			requestedURL,
			"</HTTPSessionObj:Value>",
			(props[1] == null) ? null : buildString("<HTTPSessionObj:Version>", props[1],"</HTTPSessionObj:Version>"),
			"</HTTPSessionObj:HTTP_Request_Line>",
			httpRequestHeader,
			"</HTTPSessionObj:HTTP_Client_Request></HTTPSessionObj:HTTP_Request_Response></cybox:Properties></cybox:Object></cybox:Observable>"
		);

		return httpSessionObservable;
	}

	protected static String setURIObservable(String uriID, String uri) {
		String uriObservable = buildString("<cybox:Observable xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" xmlns:stucco=\"gov.ornl.stucco\" id=\"",
			uriID,
			"\"><cybox:Object><cybox:Properties xmlns:URIObj=\"http://cybox.mitre.org/objects#URIObject-2\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"URIObj:URIObjectType\"><URIObj:Value>",
			uri,
			"</URIObj:Value></cybox:Properties></cybox:Object></cybox:Observable>"
		);

		return uriObservable;
	}

	/* 
	 * props[0] - dns record id
	 * props[1] - source
	 * props[2] - description
	 * props[3] - queried time
	 * props[4] - queried dns name id 
	 * props[5] - resolved ip name id
	 * props[6] - entry/request type
	 * props[7] - ttl
	 * props[8] - flags
	 * props[9] - id of src ip
	 * props[10] - id of dst ip
	 */
	public static String setDNSRecordObservable(String... props) { //(String dnsID, String source, String description, String dnsNameID, String reqIpID, String... props) {
		String relatedObjects = buildString(
			(props[9].isEmpty()) ? null : buildString("<cybox:Related_Object idref=\"", props[9], "\"/>"),
			(props[10].isEmpty()) ? null : buildString("<cybox:Related_Object idref=\"", props[10], "\"/>")
		);
		String dnsRecord = buildString(
			"<cybox:Observable xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" xmlns:stucco=\"gov.ornl.stucco\" xmlns:cyboxCommon=\"http://cybox.mitre.org/common-2\" xmlns:DNSRecordObj=\"http://cybox.mitre.org/objects#DNSRecordObject-2\" id=\"", 
			props[0], 
			"\"><cybox:Title>DNSRecord</cybox:Title><cybox:Observable_Source><cyboxCommon:Information_Source_Type>",
			props[1], 
			"</cyboxCommon:Information_Source_Type></cybox:Observable_Source><cybox:Object><cybox:Properties xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"DNSRecordObj:DNSRecordObjectType\"><DNSRecordObj:Description>",
			props[2],
			"</DNSRecordObj:Description> ", 
			(props[3].isEmpty()) ? "" : buildString("<DNSRecordObj:Queried_Date>", props[3], "</DNSRecordObj:Queried_Date>"),
			"<DNSRecordObj:Domain_Name object_reference=\"", 
			props[4], 
			"\"/><DNSRecordObj:IP_Address object_reference=\"", 
			props[5], 
			"\"/> ",
			(props[6].isEmpty()) ? null : buildString("<DNSRecordObj:Entry_Type>", props[6], "</DNSRecordObj:Entry_Type>"),
			(props[7].isEmpty()) ? null : buildString("<DNSRecordObj:TTL>", props[7], "</DNSRecordObj:TTL>"),
			(props[8].isEmpty()) ? null : buildString("<DNSRecordObj:Flags>", props[8], "</DNSRecordObj:Flags>"),
			"</cybox:Properties> ",
			(relatedObjects.isEmpty()) ? null : buildString("<cybox:Related_Objects>", relatedObjects, "</cybox:Related_Objects>"),
			"</cybox:Object></cybox:Observable> "
		);

		return dnsRecord.toString();
	}

	protected static String setIndicator(String indicatorID, String alternativeID, XMLGregorianCalendar timestamp, String description, String flowID, String source) {
		String indicator = buildString(
			"<indicator:Indicator xmlns:indicator=\"http://stix.mitre.org/Indicator-2\" xmlns:stixCommon=\"http://stix.mitre.org/common-1\" xmlns:stucco=\"gov.ornl.stucco\" id=\"",
			indicatorID,
			"\" ",
			(timestamp == null) ? null : buildString(" timestamp=\"", timestamp, "\" "),
			">",
			(alternativeID == null) ? null : buildString("<indicator:Alternative_ID>", alternativeID, "</indicator:Alternative_ID>"),
			(description == null) ? null : buildString("<indicator:Description>", description, "</indicator:Description>"),
			(flowID == null) ? null : buildString("<indicator:Observable idref=\"", flowID, "\"/>"),
			(source == null) ? null : buildString("<indicator:Producer><stixCommon:Identity><stixCommon:Name>", source, "</stixCommon:Name></stixCommon:Identity></indicator:Producer>"),
			"</indicator:Indicator>"
		);

		return indicator.toString();
	}

	/**
	* concatenates multiple substrings 
	*/
  protected static String buildString(Object... substrings) {
      StringBuilder str = new StringBuilder();
      for (Object substring : substrings) {
      	if (substring != null) {
          str.append(substring);
        }
      }

      return str.toString();
  }
}