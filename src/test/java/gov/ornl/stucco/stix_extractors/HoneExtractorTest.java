package gov.ornl.stucco.stix_extractors;

import java.io.IOException;
import java.io.StringReader;

import org.xml.sax.InputSource;

import org.jsoup.Jsoup;
import org.jsoup.parser.Parser;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import org.mitre.stix.stix_1.STIXPackage;

import org.xml.sax.SAXException;

import org.junit.Test;

import static org.junit.Assert.*;

/**
 * Unit test for Hone Extractor.
 */
public class HoneExtractorTest	{
	
	/**
	 * Test empty element
	 */
	@Test
	public void test_empty_element_no_header()	{

		System.out.println("STIXExtractor.HoneExtractorTest.test_empty_element_no_header()");
		String honeInfo = "";
		
		HoneExtractor honeExtractor = new HoneExtractor(honeInfo);
		STIXPackage stixPackage = honeExtractor.getStixPackage();
		
		System.out.println("Testing that Hone stixPackage is null");
		assertTrue(stixPackage == null);
	}
	
	/**
	 * Test empty element with header
	 */
	@Test
	public void test_empty_element_with_header()	{

		System.out.println("STIXExtractor.HoneExtractorTest.test_empty_element_with_header()");
		String honeInfo = 
			"user,uid,proc_pid,proc_ppid,path,argv,conn_id,timestamp_epoch_ms,source_port,dest_port,ip_version,source_ip,dest_ip,byte_cnt,packet_cnt\n" +
			",,,,,,,,,,,,,,,,,,,,,";
		
		HoneExtractor honeExtractor = new HoneExtractor(honeInfo);
		STIXPackage stixPackage = honeExtractor.getStixPackage();
		
		if (stixPackage != null) 
			System.out.println(stixPackage.toXMLString(true));

		System.out.println("Testing that Hone stixPackage is null");
		assertTrue(stixPackage == null);
	}
	
	/**
	 * Test one element
	 */
	@Test
	public void test_one_element_with_header()throws SAXException {

		System.out.println("STIXExtractor.HoneExtractorTest.test_one_element_with_header()");
		String honeInfo = 
			"user,uid,proc_pid,proc_ppid,path,argv,conn_id,timestamp_epoch_ms," +
			"source_port,dest_port,ip_version,source_ip,dest_ip,byte_cnt,packet_cnt\n" + 
			"someUser,1000,3144,3140,/usr/lib/gvfs/gvfsd-smb,test,10000,1371797596390," +
			"49870,6667,4,10.32.92.230,69.42.215.170,2068,2";
		String hostname = "Mary";

		HoneExtractor honeExtractor = new HoneExtractor(honeInfo, hostname);
		STIXPackage stixPackage = honeExtractor.getStixPackage();

		System.out.println("Validating Hone stixPackage");
		assertTrue(stixPackage.validate());

		Document doc = Jsoup.parse(stixPackage.toXMLString(), "", Parser.xmlParser());

		System.out.println("Testing 1st element:");
		Element element = doc.select("cybox|Observable:has(cybox|Title:matches(Host))").first();
		
		//hostname		
		System.out.println();
		System.out.println("Testing Hostname:");
		System.out.println("Testing Id");
		assertEquals(element.select("cybox|Object").attr("id"), "stucco:hostname-mary");
		System.out.println("Testing Name");
		assertEquals(element.select("HostnameObj|Hostname_Value").text(), "Mary");
		System.out.println("Testing Description");
		assertEquals(element.select("cybox|Object > cybox|Description").text(), "Mary");
		System.out.println("Testing Source");
		assertEquals(element.select("cybox|Observable_Source > cyboxCommon|Information_Source_Type").text(), "Hone");
		System.out.println("Testing Title");
		assertEquals(element.select("cybox|Title").text(), "Host");

		//hostname -> software relation
		System.out.println("Testing Hostname -> Software relation");
		String softwareId = element.select("cybox|Related_Object:has(cybox|Relationship:matches(^Runs$))").attr("idref");
		Element software = doc.select("[id=" + softwareId + "]").first();
		assertEquals(software.select("ProductObj|Product").text(), "/usr/lib/gvfs/gvfsd-smb");
		System.out.println("Testing Relationship");
		Element relation = element.select("cybox|Related_Object:has(cybox|Relationship:matches(^Runs$))").first();
		assertEquals(relation.select("cybox|Relationship").text(), "Runs");
		System.out.println("Testing Relation Description");
		assertEquals(relation.select("cybox|Description").text(), "Mary runs /usr/lib/gvfs/gvfsd-smb");
		System.out.println("Testing Relation Source");
		assertEquals(relation.select("cyboxCommon|Information_Source_Type").text(), "Hone");

		//hostname -> address relation
		System.out.println("Testing Hostname -> Address relation");
		String addressId = element.select("cybox|Related_Object:has(cybox|Relationship:matches(^Uses_Address$))").attr("idref");
		Element srcAddress = doc.select("[id=" + addressId + "]").first();
		String sourceIpId = srcAddress.select("SocketAddressObj|IP_Address").attr("object_reference");
		String ip = doc.select("[id= " + sourceIpId + "] > cybox|Object > cybox|Properties > AddressObj|Address_Value").text();
		assertEquals(ip, "10.32.92.230");
		String sourcePortId = srcAddress.select("SocketAddressObj|Port").attr("object_reference");
		String port = doc.select("[id= " + sourcePortId + "] > cybox|Object > cybox|Properties > PortObj|Port_Value").text();
		assertEquals(port, "49870");
		System.out.println("Testing Relationship");
		relation = element.select("cybox|Related_Object:has(cybox|Relationship:matches(^Uses_Address$))").first();
		assertEquals(relation.select("cybox|Relationship").text(), "Uses_Address");
		System.out.println("Testing Relation Description");
		assertEquals(relation.select("cybox|Description").text(), "Mary uses address 10.32.92.230, port 49870");
		System.out.println("Testing Relation Source");
		assertEquals(relation.select("cyboxCommon|Information_Source_Type").text(), "Hone");

		//software 
		element = doc.select("cybox|Observable:has(cybox|Title:matches(Software))").first();
		System.out.println();
		System.out.println("Testing Software:");
		Element softwarePart = element.select("cybox|Observable").first();
		System.out.println("Testing Id");
		assertEquals(softwarePart.select("cybox|Object").attr("id"), "stucco:software-_usr_lib_gvfs_gvfsd-smb");
		System.out.println("Testing Name");
		assertEquals(softwarePart.select("ProductObj|Product").text(), "/usr/lib/gvfs/gvfsd-smb");
		System.out.println("Testing Source");
		assertEquals(softwarePart.select("cybox|Observable > cybox|Observable_Source > cyboxCommon|Information_Source_Type").first().text(), "Hone");
		System.out.println("Testing Title");
		assertEquals(softwarePart.select("cybox|Observable > cybox|Title").first().text(), "Software");
		System.out.println("Testing Description");
		assertEquals(softwarePart.select("cybox|Object > cybox|Description").text(), "/usr/lib/gvfs/gvfsd-smb");
		System.out.println("Testing PID");
		assertEquals(element.select("ProcessObj|PID").text(), "3144");
		System.out.println("Testing PPID");
		assertEquals(element.select("ProcessObj|Parent_PID").text(), "3140");
		System.out.println("Testing Name");
		assertEquals(element.select("ProcessObj|Name").text(), "/usr/lib/gvfs/gvfsd-smb");
		System.out.println("Testing Arguments");
		assertEquals(element.select("ProcessObj|Argument").text(), "test");

		//software -> flow relation
		System.out.println("Testing Software -> Flow relation:");
		String flowId = element.select("cybox|Related_Object:has(cybox|Relationship:matches(^Moved_By$))").attr("idref");
		Element flow = doc.select("[id=" + flowId + "]").first();
		assertEquals(flow.select("cybox|Description").text(), "10.32.92.230, port 49870 to 69.42.215.170, port 6667");
		System.out.println("Testing Relationship");
		relation = element.select("cybox|Related_Object:has(cybox|Relationship:matches(^Moved_By$))").first();
		assertEquals(relation.select("cybox|Relationship").text(), "Moved_By");
		System.out.println("Testing Relation Description");
		assertEquals(relation.select("cybox|Description").text(), "/usr/lib/gvfs/gvfsd-smb moved by flow 10.32.92.230, port 49870 to 69.42.215.170, port 6667");
		System.out.println("Testing Relation Source");
		assertEquals(relation.select("cybox|Discovery_Method > cyboxCommon|Information_Source_Type").text(), "Hone");

		//software -> account
		System.out.println("Testing Software -> Account relation:");
		String accountId = element.select("cybox|Related_Object:has(cybox|Relationship:matches(^Runs_As$))").attr("idref");
		Element account = doc.select("[id=" + accountId + "]").first();
		assertEquals(account.select("AccountObj|Description").text(), "uid 1000 on host Mary");
		System.out.println("Testing Relationship");
		relation = element.select("cybox|Related_Object:has(cybox|Relationship:matches(^Runs_As$))").first();
		assertEquals(relation.select("cybox|Relationship").text(), "Runs_As");
		System.out.println("Testing Relation Description");
		assertEquals(relation.select("cybox|Description").text(), "/usr/lib/gvfs/gvfsd-smb runs as uid 1000 on host Mary");
		System.out.println("Testing Relation Source");
		assertEquals(relation.select("cybox|Discovery_Method > cyboxCommon|Information_Source_Type").text(), "Hone");

		//account
		System.out.println();
		element = doc.select("cybox|Observable:has(cybox|Title:matches(Account))").first();
		System.out.println("Testing Account:");
		System.out.println("Testing Id");
		assertEquals(element.select("cybox|Object").attr("id"), "stucco:account-mary_1000");
		System.out.println("Testing Title");
		assertEquals(element.select("cybox|Title").text(), "Account");
		System.out.println("Testing Full Name");
		assertEquals(element.select("UserAccountObj|Full_Name").text(), "someUser");
		System.out.println("Testing Username");
		assertEquals(element.select("UserAccountObj|Username").text(), "1000");
		System.out.println("Testing Source");
		assertEquals(element.select("cybox|Observable > cybox|Observable_Source > cyboxCommon|Information_Source_Type").text(), "Hone");
		System.out.println("Testing Description");
		assertEquals(element.select("AccountObj|Description").text(), "uid 1000 on host Mary");
		Elements elements = doc.select("cybox|Observable:has(cybox|Title:matches(^Address$))");

		sourceIpId = null;
		String destIpId = null;
		sourcePortId = null;
		String destPortId = null;

		for (Element address : elements)	{

			//source address
			if (!address.select("cybox|Description:contains(49870)").text().isEmpty())	{
				System.out.println();
				System.out.println("Testing Source Address:");
				System.out.println("Testing Title");
				assertEquals(address.select("cybox|Title").text(), "Address");
				System.out.println("Testing Source");
				assertEquals(address.select("cyboxCommon|Information_Source_Type").text(), "Hone");
				System.out.println("Testing Description");
				assertEquals(address.select("cybox|Description").text(), "10.32.92.230, port 49870");

				//source address -> source IP
				System.out.println("Testing Address -> IP relation");
				sourceIpId = address.select("SocketAddressObj|IP_Address").attr("object_reference");
				ip = doc.select("[id= " + sourceIpId + "] > cybox|Object > cybox|Properties > AddressObj|Address_Value").text();
				assertEquals(ip, "10.32.92.230");

				//source address -> source Port
				System.out.println("Testing Address -> Port relation");
				sourcePortId = address.select("SocketAddressObj|Port").attr("object_reference");
				port = doc.select("[id= " + sourcePortId + "] > cybox|Object > cybox|Properties > PortObj|Port_Value").text();
				assertEquals(port, "49870");
			}

			//destination address
			if (!address.select("cybox|Description:contains(6667)").text().isEmpty())	{
				System.out.println();
				System.out.println("Testing Destination Address:");
				System.out.println("Testing Title");
				assertEquals(address.select("cybox|Title").text(), "Address");
				System.out.println("Testing Source");
				assertEquals(address.select("cyboxCommon|Information_Source_Type").text(), "Hone");
				System.out.println("Testing Description");
				assertEquals(address.select("cybox|Description").text(), "69.42.215.170, port 6667");

				//dest address -> dest IP
				System.out.println("Testing Address -> IP relation");
				destIpId = address.select("SocketAddressObj|IP_Address").attr("object_reference");
				ip = doc.select("[id= " + destIpId + "] > cybox|Object > cybox|Properties > AddressObj|Address_Value").text();
				assertEquals(ip, "69.42.215.170");

				//dest address -> dest Port
				System.out.println("Testing Address -> Port relation");
				destPortId = address.select("SocketAddressObj|Port").attr("object_reference");
				port = doc.select("[id= " + destPortId + "] > cybox|Object > cybox|Properties > PortObj|Port_Value").text();
				assertEquals(port, "6667");
			}
		}

		//source IP
		System.out.println();
		System.out.println("Testing Source IP:");
		if (sourceIpId != null)	{
			element = doc.select("[id= " + sourceIpId + "]").first();
			System.out.println("Testing Title");
			assertEquals(element.select("cybox|Title").text(), "IP");
			System.out.println("Testing Source");
			assertEquals(element.select("cyboxCommon|Information_Source_Type").text(), "Hone");
			System.out.println("Testing IP value");
			assertEquals(element.select("AddressObj|Address_Value").text(), "10.32.92.230");
			System.out.println("Testing Description");
			assertEquals(element.select("cybox|Description").text(), "10.32.92.230");
		}
		else	{
			System.out.println("ERROR: Could not verify Source IP or Source Address");
			assertTrue(false);
		}

		//destination IP
		System.out.println();
		System.out.println("Testing Destination IP:");
		if (destIpId != null)	{
			element = doc.select("[id= " + destIpId + "]").first();
			System.out.println("Testing Title");
			assertEquals(element.select("cybox|Title").text(), "IP");
			System.out.println("Testing Source");
			assertEquals(element.select("cyboxCommon|Information_Source_Type").text(), "Hone");
			System.out.println("Testing IP value");
			assertEquals(element.select("AddressObj|Address_Value").text(), "69.42.215.170");
			System.out.println("Testing Description");
			assertEquals(element.select("cybox|Description").text(), "69.42.215.170");
		}
		else	{
			System.out.println("ERROR: Could not verify Destination IP or Destination Address");
			assertTrue(false);
		}

		//source Port
		System.out.println();
		System.out.println("Testing Source Port:");
		if (sourcePortId != null)	{
			element = doc.select("[id=" + sourcePortId + "]").first();
			System.out.println("Testing Title");
			assertEquals(element.select("cybox|Title").text(), "Port");
			System.out.println("Testing Source");
			assertEquals(element.select("cyboxCommon|Information_Source_Type").text(), "Hone");
			System.out.println("Testing Port value");
			assertEquals(element.select("PortObj|Port_Value").text(), "49870");
			System.out.println("Testing Description");
			assertEquals(element.select("cybox|Description").text(), "49870");
		}
		else	{
			System.out.println("ERROR: Could not verify Source Port or Source Address");
			assertTrue(false);
		}

		//destination Port
		System.out.println();
		System.out.println("Testing Destination Port:");
		if (destPortId != null)	{
			element = doc.select("[id=" + destPortId + "]").first();
			System.out.println("Testing Title");
			assertEquals(element.select("cybox|Title").text(), "Port");
			System.out.println("Testing Source");
			assertEquals(element.select("cyboxCommon|Information_Source_Type").text(), "Hone");
			System.out.println("Testing Port value");
			assertEquals(element.select("PortObj|Port_Value").text(), "6667");
			System.out.println("Testing Description");
			assertEquals(element.select("cybox|Description").text(), "6667");
		}
		else	{
			System.out.println("ERROR: Could not verify Source Port or Source Address");
			assertTrue(false);
		}

		//flow
		System.out.println();
		element = doc.select("cybox|Observable:has(cybox|Title:matches(^Flow$))").first();
		System.out.println("Testing Flow:");
		System.out.println("Testing Title");
		assertEquals(element.select("cybox|Title").text(), "Flow");
		System.out.println("Testing Source");
		assertEquals(element.select("cyboxCommon|Information_Source_Type").text(), "Hone");
		System.out.println("Testing ID");
		assertEquals(element.select("cybox|Object").attr("id"), "stucco:flow-169893094_49870-1160435626_6667");
		String srcSocketId = element.select("NetFlowObj|Src_Socket_Address").attr("object_reference");
		String destSocketId = element.select("NetFlowObj|Dest_Socket_Address").attr("object_reference");
		Element srcSocket = doc.select("[id=" + srcSocketId + "]").first();
		Element destSocket = doc.select("[id=" + destSocketId + "]").first();

		//flow -> source address
		System.out.println("Testing Flow -> Source Address relation");
		System.out.println("Testing Flow Source IP");
		sourceIpId = srcSocket.select("SocketAddressObj|IP_Address").attr("object_reference");
		ip = doc.select("[id= " + sourceIpId + "] > cybox|Object > cybox|Properties > AddressObj|Address_Value").text();
		assertEquals(ip, "10.32.92.230");
		System.out.println("Testing Flow Source Port");
		sourcePortId = srcSocket.select("SocketAddressObj|Port").attr("object_reference");
		port = doc.select("[id= " + sourcePortId + "] > cybox|Object > cybox|Properties > PortObj|Port_Value").text();
		assertEquals(port, "49870");

		//flow -> dest address
		System.out.println("Testing Flow -> Dest Address relation");
		System.out.println("Testing Flow Dest IP");
		destIpId = destSocket.select("SocketAddressObj|IP_Address").attr("object_reference");
		ip = doc.select("[id= " + destIpId + "] > cybox|Object > cybox|Properties > AddressObj|Address_Value").text();
		assertEquals(ip, "69.42.215.170");
		System.out.println("Testing Flow Dest Port");
		destPortId = destSocket.select("SocketAddressObj|Port").attr("object_reference");
		port = doc.select("[id= " + destPortId + "] > cybox|Object > cybox|Properties > PortObj|Port_Value").text();
		assertEquals(port, "6667");
		System.out.println("Testing Destcription");
		assertEquals(element.select("cybox|Description").text(), "10.32.92.230, port 49870 to 69.42.215.170, port 6667");
		System.out.println("Testing Start Time");
		assertEquals(element.select("cyboxCommon|Property[name=Start_Time]").text(), "1371797596390");
		System.out.println("Testing Total Packets");
		assertEquals(element.select("cyboxCommon|Property[name=Total_Packets]").text(), "2");
		System.out.println("Testing Total Bytes");
		assertEquals(element.select("cyboxCommon|Property[name=Total_Bytes]").text(), "2068");
	}
	
	/**
	 * Test two elements
	 */
	@Test
	public void test_two_elements()	throws SAXException {

		System.out.println("STIXExtractor.HoneExtractorTest.test_one_element_with_header()");
		String honeInfo = 
			"user,uid,proc_pid,proc_ppid,path,argv,conn_id,timestamp_epoch_ms," +
			"source_port,dest_port,ip_version,source_ip,dest_ip,byte_cnt,packet_cnt\n" + 
			"someUser,1000,3144,3140,/usr/lib/gvfs/gvfsd-smb,test,10000,1371797596390," +
			"49870,6667,4,10.32.92.230,69.42.215.170,2068,2\n" +
			"someUser,1000,3144,3140,/usr/lib/gvfs/gvfsd-smb,test,10000,1371797596390," +
			"49870,6667,4,10.32.92.230,69.42.215.170,2068,2";
		String hostname = "Mary";

		HoneExtractor honeExtractor = new HoneExtractor(honeInfo, hostname);
		STIXPackage stixPackage = honeExtractor.getStixPackage();
		
		System.out.println("Validating Hone stixPackage");
		assertTrue(stixPackage.validate());
	}
}
