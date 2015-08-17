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

			System.out.println();
			System.out.println("Testing Flow content:");

			System.out.println("Testing ID");
			assertEquals(element.select("cybox|Object").attr("id"), "stucco:flow-168430081_56867-168430180_22");
			System.out.println("Testing Description");
			assertEquals(element.select("cybox|Description").text(), "10.10.10.1, port 56867 to 10.10.10.100, port 22");
			System.out.println("Testing Title");
			assertEquals(element.select("cybox|Title").text(), "Flow");
			System.out.println("Testing Source");
			assertEquals(element.select("cyboxCommon|Information_Source_Type").text(), "Argus");
			System.out.println("Testing Protocol");
			assertEquals(element.select("NetFlowObj|IP_Protocol").text(), "6");
			System.out.println("Testing TotalBytes");
			assertEquals(element.select("[name=TotBytes]").text(), "585");
			System.out.println("Testing StartTime");
			assertEquals(element.select("[name=StartTime]").text(), "1373553586.136399");
			System.out.println("Testing Teting Flags");
			assertEquals(element.select("[name=Flgs]").text(), "e s");
			System.out.println("Testing Direction");
			assertEquals(element.select("[name=Dir]").text(), "->");
			System.out.println("Testing TotPkts");
			assertEquals(element.select("[name=TotPkts]").text(), "8");
			System.out.println("Testing State");
			assertEquals(element.select("cybox|State").text(), "REQ");
		
			System.out.println("Testing Flow Source Address -> Address -> IP, Port reference");

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
			
			System.out.println("Testing Flow Destination Address -> Address -> IP, Port reference");
			
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
		System.out.println();
		System.out.println("Testing Address content:");
		
		elements = doc.select("cybox|Observable:has(cybox|Title:matches(^Address\\Z))");

		assertEquals(elements.size(), 2);
	
		for (Element element : elements)	{
			if (element.select("cybox|Object").attr("id").equals("stucco:address-168430081_56867"))	{
				System.out.println("Testing Title");
				assertEquals(element.select("cybox|Title").text(), "Address");
				System.out.println("Testing Source");
				assertEquals(element.select("cyboxCommon|Information_Source_Type").text(), "Argus");
				System.out.println("Testing Description");
				assertEquals(element.select("cybox|Description").text(), "10.10.10.1, port 56867");
				
				System.out.println("Testing Address -> IP reference");
				String ipId = element.select("SocketAddressObj|IP_Address").attr("object_reference");
				String ip = doc.select("[id= " + ipId + "] > cybox|Object > cybox|Properties > AddressObj|Address_Value").text();
				assertEquals(ip, "10.10.10.1");
				
				System.out.println("Testing Address -> Port reference");
				String portId = element.select("SocketAddressObj|Port").attr("object_reference");
				String port = doc.select("[id= " + portId + "] > cybox|Object > cybox|Properties > PortObj|Port_Value").text();
				assertEquals(port, "56867");
			} else {			
				if (element.select("cybox|Object").attr("id").equals("stucco:address-168430180_22"))	{
					System.out.println("Testing Title");
					assertEquals(element.select("cybox|Title").text(), "Address");
					System.out.println("Testing Source");
					assertEquals(element.select("cyboxCommon|Information_Source_Type").text(), "Argus");
					System.out.println("Testing Description");
					assertEquals(element.select("cybox|Description").text(), "10.10.10.100, port 22");
				
					System.out.println("Testing Address -> IP reference");
					String ipId = element.select("SocketAddressObj|IP_Address").attr("object_reference");
					String ip = doc.select("[id= " + ipId + "] > cybox|Object > cybox|Properties > AddressObj|Address_Value").text();
					assertEquals(ip, "10.10.10.100");
				
					System.out.println("Testing Address -> Port reference");
					String portId = element.select("SocketAddressObj|Port").attr("object_reference");
					String port = doc.select("[id= " + portId + "] > cybox|Object > cybox|Properties > PortObj|Port_Value").text();
					assertEquals(port, "22");
				} else { 
					System.out.println("ERROR: Could not find Address content");
					assertTrue(false);
				}	
			}			
		}
//testing IP	
		System.out.println();
		System.out.println("Testing IP content:");
		
		elements = doc.select("cybox|Observable:has(cybox|Title:matches(^IP\\Z))");
		
		assertEquals(elements.size(), 2);
	
		for (Element element : elements)	{
			if (element.select("cybox|Object").attr("id").equals("stucco:ip-168430081"))	{
				System.out.println("Testing Title");
				assertEquals(element.select("cybox|Title").text(), "IP");
				System.out.println("Testing Source");
				assertEquals(element.select("cyboxCommon|Information_Source_Type").text(), "Argus");
				System.out.println("Testing IP Long (ID)");
				assertEquals(element.select("cybox|Object").attr("id"), "stucco:ip-168430081");
				System.out.println("Testing IP String");
				assertEquals(element.select("AddressObj|Address_Value").text(), "10.10.10.1");
				System.out.println("Testing Description");
				assertEquals(element.select("cybox|Description").text(), "10.10.10.1");
			} else {
				if (element.select("cybox|Object").attr("id").equals("stucco:ip-168430180"))	{
					System.out.println("Testing Title");
					assertEquals(element.select("cybox|Title").text(), "IP");
					System.out.println("Testing Source");
					assertEquals(element.select("cyboxCommon|Information_Source_Type").text(), "Argus");
					System.out.println("Testing IP Long (ID)");
					assertEquals(element.select("cybox|Object").attr("id"), "stucco:ip-168430180");
					System.out.println("Testing IP String");
					assertEquals(element.select("AddressObj|Address_Value").text(), "10.10.10.100");
					System.out.println("Testing Description");
					assertEquals(element.select("cybox|Description").text(), "10.10.10.100");
				} else { 
					System.out.println("ERROR: Could not find IP content");
					assertTrue(false);
				}	
			}	
		}
//testing port										
		System.out.println();
		System.out.println("Testing Port content:");
		
		elements = doc.select("cybox|Observable:has(cybox|Title:matches(^Port\\Z))");
		
		assertEquals(elements.size(), 2);
	
		for (Element element : elements)	{					
			if(element.select("cybox|Object").attr("id").equals("stucco:port-56867"))	{
				System.out.println("Testing Title");
				assertEquals(element.select("cybox|Title").text(), "Port");
				System.out.println("Testing Source");
				assertEquals(element.select("cyboxCommon|Information_Source_Type").text(), "Argus");
				System.out.println("Testing Port value");
				assertEquals(element.select("PortObj|Port_Value").text(), "56867");
				System.out.println("Testing Description");
				assertEquals(element.select("cybox|Description").text(), "56867");
			}
			if(element.select("cybox|Object").attr("id").equals("stucco:port-22"))	{
				System.out.println("Testing Title");
				assertEquals(element.select("cybox|Title").text(), "Port");
				System.out.println("Testing Source");
				assertEquals(element.select("cyboxCommon|Information_Source_Type").text(), "Argus");
				System.out.println("Testing Port value");
				assertEquals(element.select("PortObj|Port_Value").text(), "22");
				System.out.println("Testing Description");
				assertEquals(element.select("cybox|Description").text(), "22");
			}
		}
	}
}
