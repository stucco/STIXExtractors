package STIXExtractor;

import java.io.File;
import java.io.IOException;
import java.io.StringReader;
import java.net.URL;
import java.nio.charset.Charset;

import org.xml.sax.InputSource;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;

import org.json.*;
import org.jsoup.*;
import org.jsoup.parser.Parser;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import org.mitre.stix.stix_1.STIXPackage;

import org.junit.Test;

import static org.junit.Assert.*;

import STIXExtractor.ArgusExtractor;

/**
 * Unit test for Argus Extractor.
 */
public class ArgusExtractorTest	{
	
	/**
	 * Test one element
	 */
	@Test
	public void test_one_element_no_header()	{

		String[] headers = "StartTime,Flgs,Proto,SrcAddr,Sport,Dir,DstAddr,Dport,TotPkts,TotBytes,State".split(",");
		String argusInfo = "1373553586.136399, e s,6,10.10.10.1,56867,->,10.10.10.100,22,8,585,REQ";
		
		ArgusExtractor argusExtractor = new ArgusExtractor(headers, argusInfo);
		STIXPackage stixPackage = argusExtractor.getStixPackage();
		
		System.out.println("Validating Argus stixPackage");

		assertTrue(argusExtractor.validate(stixPackage));
		
		Document doc = Jsoup.parse(stixPackage.toXMLString(), "", Parser.xmlParser());
//testing flow 									
		Elements elements = doc.select("cybox|Observable:has(cybox|Title:matches(^Flow\\Z))");

		assertEquals(elements.size(), 1);

		for (Element element : elements)	{

			System.out.println("Testing Flow content");

			assertEquals(element.select("cybox|Object").attr("id"), "stucco:flow-10.10.10.1-56867-10.10.10.100-22");
			assertEquals(element.select("cybox|Description").text(), "10.10.10.1, port 56867 to 10.10.10.100, port 22");
			assertEquals(element.select("cybox|Title").text(), "Flow");
			assertEquals(element.select("cyboxCommon|Information_Source_Type").text(), "Argus");
			assertEquals(element.select("NetFlowObj|IP_Protocol").text(), "6");
			assertEquals(element.select("[name=TotBytes]").text(), "585");
			assertEquals(element.select("[name=StartTime]").text(), "1373553586.136399");
			assertEquals(element.select("[name=Flgs]").text(), "e s");
			assertEquals(element.select("[name=Dir]").text(), "->");
			assertEquals(element.select("[name=TotPkts]").text(), "8");
			assertEquals(element.select("cybox|State").text(), "REQ");
		
			System.out.println("Testing Flow Source Address -> Address -> IP, Port relation");

			//checking source address and port (edge flow - > address -> ip, port)
			String srcAddressId = element.select("NetFlowObj|Src_Socket_Address").attr("object_reference");
			String srcIpId = doc.select("cybox|Observable:has(cybox|Title:matches(^Address\\Z))[id=" + srcAddressId + 
					"] > cybox|object > cybox|Properties > socketaddressobj|ip_address").attr("object_reference");
			String srcIp = doc.select("[id= " + srcIpId + "] > cybox|Object > cybox|Properties > AddressObj|Address_Value").text();
			assertEquals(srcIp, "10.10.10.1");
			
			String srcPortId = doc.select("cybox|Observable:has(cybox|Title:matches(^Address\\Z))[id=" + srcAddressId + 
					"] > cybox|object > cybox|Properties > socketaddressobj|port").attr("object_reference");
			String srcPort = doc.select("[id= " + srcPortId + "] > cybox|Object > cybox|Properties > PortObj|Port_Value").text();
			assertEquals(srcPort, "56867");
			
			System.out.println("Testing Flow Destination Address -> Address -> IP, Port relation");
			
			//checking destination address and port (edge flow -> address -> ip, port)
			String dstAddressId = element.select("NetFlowObj|Dest_Socket_Address").attr("object_reference");
			String dstIpId = doc.select("[id=" + dstAddressId + "] > cybox|object > cybox|Properties > socketaddressobj|ip_address").attr("object_reference");
			String dstIp = doc.select("[id= " + dstIpId + "] > cybox|Object > cybox|Properties > AddressObj|Address_Value").text();
			assertEquals(dstIp, "10.10.10.100");
			
			String dstPortId = doc.select("cybox|Observable:has(cybox|Title:matches(^Address\\Z))[id=" + dstAddressId + 
					"] > cybox|object > cybox|Properties > socketaddressobj|port").attr("object_reference");
			String dstPort = doc.select("[id= " + dstPortId + "] > cybox|Object > cybox|Properties > PortObj|Port_Value").text();
			assertEquals(dstPort, "22");
		}			
//testing address	
		System.out.println("Testing Address content");
		
		elements = doc.select("cybox|Observable:has(cybox|Title:matches(^Address\\Z))");

		assertEquals(elements.size(), 2);
	
		for (Element element : elements)	{
			if(element.select("cybox|Object").attr("id").equals("stucco:address-10.10.10.1-56867"))	{
				assertEquals(element.select("cyboxCommon|Information_Source_Type").text(), "Argus");
				assertEquals(element.select("cybox|Description").text(), "10.10.10.1, port 56867");
				
				String ipId = element.select("SocketAddressObj|IP_Address").attr("object_reference");
				String ip = doc.select("[id= " + ipId + "] > cybox|Object > cybox|Properties > AddressObj|Address_Value").text();
				assertEquals(ip, "10.10.10.1");
				
				String portId = element.select("SocketAddressObj|Port").attr("object_reference");
				String port = doc.select("[id= " + portId + "] > cybox|Object > cybox|Properties > PortObj|Port_Value").text();
				assertEquals(port, "56867");
			}			
			if(element.select("cybox|Object").attr("id").equals("stucco:address-10.10.10.100-22"))	{
				assertEquals(element.select("cyboxCommon|Information_Source_Type").text(), "Argus");
				assertEquals(element.select("cybox|Description").text(), "10.10.10.100, port 22");
				
				String ipId = element.select("SocketAddressObj|IP_Address").attr("object_reference");
				String ip = doc.select("[id= " + ipId + "] > cybox|Object > cybox|Properties > AddressObj|Address_Value").text();
				assertEquals(ip, "10.10.10.100");
				
				String portId = element.select("SocketAddressObj|Port").attr("object_reference");
				String port = doc.select("[id= " + portId + "] > cybox|Object > cybox|Properties > PortObj|Port_Value").text();
				assertEquals(port, "22");
			}			
		}
//testing IP	
		System.out.println("Testing IP content");
		
		elements = doc.select("cybox|Observable:has(cybox|Title:matches(^IP\\Z))");
		
		assertEquals(elements.size(), 2);
	
		for (Element element : elements)	{
			if(element.select("cybox|Object").attr("id").equals("stucco:ip-10.10.10.1"))	{
				assertEquals(element.select("cyboxCommon|Information_Source_Type").text(), "Argus");
				assertEquals(element.select("AddressObj|Address_Value").text(), "10.10.10.1");
				assertEquals(element.select("cybox|Description").text(), "10.10.10.1");
			}
			if(element.select("cybox|Object").attr("id").equals("stucco:ip-10.10.10.100"))	{
				assertEquals(element.select("cyboxCommon|Information_Source_Type").text(), "Argus");
				assertEquals(element.select("AddressObj|Address_Value").text(), "10.10.10.100");
				assertEquals(element.select("cybox|Description").text(), "10.10.10.100");
			}
		}
//testing port										
		System.out.println("Testing Port content");
		
		elements = doc.select("cybox|Observable:has(cybox|Title:matches(^Port\\Z))");
		
		assertEquals(elements.size(), 2);
	
		for (Element element : elements)	{					
			if(element.select("cybox|Object").attr("id").equals("stucco:port-56867"))	{
				assertEquals(element.select("cyboxCommon|Information_Source_Type").text(), "Argus");
				assertEquals(element.select("PortObj|Port_Value").text(), "56867");
				assertEquals(element.select("cybox|Description").text(), "56867");
			}
			if(element.select("cybox|Object").attr("id").equals("stucco:port-22"))	{
				assertEquals(element.select("cyboxCommon|Information_Source_Type").text(), "Argus");
				assertEquals(element.select("PortObj|Port_Value").text(), "22");
				assertEquals(element.select("cybox|Description").text(), "22");
			}
		}
	}
}
