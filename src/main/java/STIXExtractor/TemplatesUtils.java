package STIXExtractor;

import java.util.Set;
import java.util.HashSet;
import java.util.UUID;

import org.json.JSONObject;

import org.apache.commons.csv.CSVRecord;

public abstract class TemplatesUtils {

	
	protected static String setIPObservable(String ip, String ipID, String source) {
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

	protected static String setPortObservable(String port, String portID, String source) {
		String portObservable = buildString("<cybox:Observable id=\"stucco:port-",
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
		String addressObservable = buildString("<cybox:Observable id=\"stucco:address-",
			addressID, 
			"\" xmlns:SocketAddressObj=\"http://cybox.mitre.org/objects#SocketAddressObject-1\" xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" xmlns:cyboxCommon=\"http://cybox.mitre.org/common-2\" xmlns:stucco=\"gov.ornl.stucco\"><cybox:Title>Address</cybox:Title><cybox:Observable_Source><cyboxCommon:Information_Source_Type>",
			source,
			"</cyboxCommon:Information_Source_Type></cybox:Observable_Source><cybox:Object><cybox:Description>",
			ip, 
			", port ",
			port,
			"</cybox:Description><cybox:Properties xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"SocketAddressObj:SocketAddressObjectType\">",
			(ipID == null) ? null : buildString(
				"<SocketAddressObj:IP_Address object_reference=\"stucco:ip-",
				ipID,
				"\"/>"
			),
			(portID == null) ? null : buildString(
				"<SocketAddressObj:Port object_reference=\"stucco:port-",
				portID,
				"\"/>"
			),
			"</cybox:Properties></cybox:Object></cybox:Observable>"
		);

		return addressObservable;
	}

	protected static String setFlowObservable(String flowID, String srcIp, String srcPort, String srcAddressID, String dstIp, String dstPort, String dstAddressID, String protocol, String sourceString, Set<String> headersSet, CSVRecord record) {
		String customProperties = null;
		for (String header : headersSet) {
			if (!record.get(header).isEmpty()) {
				customProperties = buildString(customProperties, "<cyboxCommon:Property name=\"", header, "\">", record.get(header), "</cyboxCommon:Property>");
			}
		}

		String networkFlow = buildString(
			(srcAddressID == null) ? null : buildString(
				"<NetFlowObj:Src_Socket_Address object_reference=\"stucco:address-",
				srcAddressID,
				"\"/>"
			),
			(dstAddressID == null) ? null : buildString(
				"<NetFlowObj:Dest_Socket_Address object_reference=\"stucco:address-",
				dstAddressID,
				"\"/>"
			),
			(protocol == null) ? null : buildString(
				"<NetFlowObj:IP_Protocol>",
				protocol,
				"</NetFlowObj:IP_Protocol>"
			)
		);

		String networkFlowLabel = buildString(
			(networkFlow == null) ? null : buildString(
				"<NetFlowObj:Network_Flow_Label>",
				networkFlow,
				"</NetFlowObj:Network_Flow_Label>"
			)
		);
		
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
			(customProperties == null ) ? null : buildString(
				"<cyboxCommon:Custom_Properties>", 
				customProperties, 
				"</cyboxCommon:Custom_Properties>"
			),
			customProperties,
			networkFlowLabel,
			"</cybox:Properties></cybox:Object></cybox:Observable>"
		);

		return flowObservable;
	}

	protected static String setDNSNameObservable(String dnsID, String dnsName, String dnsIpID, String sourceString) {
		String relatedObject = (dnsIpID == null) ? null : buildString(
			"<cybox:Related_Objects><cybox:Related_Object idref=\"stucco:ip-",
			dnsIpID,
			"\"><cybox:Relationship>Resolved_To</cybox:Relationship></cybox:Related_Object></cybox:Related_Objects>"
		);
		String dnsObservable = buildString("<cybox:Observable xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" xmlns:stucco=\"gov.ornl.stucco\" id=\"stucco:dnsName-",
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
			(props[7] == null) ? null : buildString("<HTTPSessionObj:Domain_Name object_reference=\"stucco:dnsName-", props[7], "\" />"),
			(props[8] == null) ? null : buildString("<HTTPSessionObj:Port object_reference=\"stucco:port-", props[8], "\" />")
		);
		String rawHeader = buildString(
			"<HTTPSessionObj:Raw_Header>", props[2], "</HTTPSessionObj:Raw_Header>"
		);
		String parsedHeader = buildString(
			"<HTTPSessionObj:Parsed_Header>",
			(props[3] == null) ? null : buildString("<HTTPSessionObj:Accept_Language>", props[3], "</HTTPSessionObj:Accept_Language>"),
			(props[4] == null) ? null : buildString("<HTTPSessionObj:Content_Length>", props[4], "</HTTPSessionObj:Content_Length>"),
			(props[5] == null) ? null : buildString("<HTTPSessionObj:Date>", props[5], "</HTTPSessionObj:Date>"),
			(props[6] == null) ? null : buildString("<HTTPSessionObj:From object_reference=\"stucco:ip-", props[6],"\" />"),
			(host == null) ? null : buildString("<HTTPSessionObj:Host>", host, "</HTTPSessionObj:Host>"),
			(props[9] == null) ? null : buildString("<HTTPSessionObj:Referer object_reference=\"stucco:Observable-", props[9], "\" />"),
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

		String httpSessionObservable = buildString("<cybox:Observable xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" xmlns:stucco=\"gov.ornl.stucco\" id=\"stucco:httpRequest-",
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
		String uriObservable = buildString("<cybox:Observable xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" xmlns:stucco=\"gov.ornl.stucco\" id=\"stucco:Observable-",
			uriID,
			"\"><cybox:Object><cybox:Properties xmlns:URIObj=\"http://cybox.mitre.org/objects#URIObject-2\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"URIObj:URIObjectType\"><URIObj:Value>",
			uri,
			"</URIObj:Value></cybox:Properties></cybox:Object></cybox:Observable>"
		);

		return uriObservable;
	}

	/**
	* concatenates multiple substrings 
	*/
  protected static String buildString(Object... substrings) {
      StringBuilder str = new StringBuilder();
      for (Object substring : substrings) {
          str.append(substring);
      }

      return str.toString();
  }
}