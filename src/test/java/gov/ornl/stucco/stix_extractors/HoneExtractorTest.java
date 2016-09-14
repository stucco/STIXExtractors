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
		Element host = doc.select("cybox|Observable:has(cybox|Title:matches(Host))").first();
		
		//hostname		
		System.out.println();
		System.out.println("Testing Hostname:");
		System.out.println("Testing Id");
		assertEquals(host.select("cybox|Object").attr("id"), "stucco:hostname-mary");
		System.out.println("Testing Name");
		assertEquals(host.select("HostnameObj|Hostname_Value").text(), "Mary");
		System.out.println("Testing Description");
		assertEquals(host.select("cybox|Object > cybox|Description").text(), "Mary");
		System.out.println("Testing Source");
		assertEquals(host.select("cybox|Observable_Source > cyboxCommon|Information_Source_Type").text(), "Hone");
		System.out.println("Testing Title");
		assertEquals(host.select("cybox|Title").text(), "Host");

		//software 
		Element software = doc.select("cybox|Observable:has(cybox|Title:matches(Software))").first();
		String softwareID = software.attr("id");
		System.out.println();
		System.out.println("Testing Software:");
		Element softwarePart = software.select("cybox|Observable").first();
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
		assertEquals(software.select("ProcessObj|PID").text(), "3144");
		System.out.println("Testing PPID");
		assertEquals(software.select("ProcessObj|Parent_PID").text(), "3140");
		System.out.println("Testing Name");
		assertEquals(software.select("ProcessObj|Name").text(), "/usr/lib/gvfs/gvfsd-smb");
		System.out.println("Testing Arguments");
		assertEquals(software.select("ProcessObj|Argument").text(), "test");

		//account
		System.out.println();
		Element account = doc.select("cybox|Observable:has(cybox|Title:matches(Account))").first();
		String accountID = account.attr("id");
		System.out.println("Testing Account:");
		System.out.println("Testing Id");
		assertEquals(account.select("cybox|Object").attr("id"), "stucco:account-mary_1000");
		System.out.println("Testing Title");
		assertEquals(account.select("cybox|Title").text(), "Account");
		System.out.println("Testing Full Name");
		assertEquals(account.select("UserAccountObj|Full_Name").text(), "someUser");
		System.out.println("Testing Username");
		assertEquals(account.select("UserAccountObj|Username").text(), "1000");
		System.out.println("Testing Source");
		assertEquals(account.select("cybox|Observable > cybox|Observable_Source > cyboxCommon|Information_Source_Type").text(), "Hone");
		System.out.println("Testing Description");
		assertEquals(account.select("AccountObj|Description").text(), "uid 1000 on host Mary");
		Elements elements = doc.select("cybox|Observable:has(cybox|Title:matches(^Address$))");

		String sourceIpId = null;
		String destIpId = null;
		String sourcePortId = null;
		String destPortId = null;
		String srcAddressID = null;
		String dstAddressID = null;

		for (Element address : elements)	{

			//source address
			if (!address.select("cybox|Description:contains(49870)").text().isEmpty())	{
				srcAddressID = address.attr("id");
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
				String ip = doc.select("[id= " + sourceIpId + "] > cybox|Object > cybox|Properties > AddressObj|Address_Value").text();
				assertEquals(ip, "10.32.92.230");

				//source address -> source Port
				System.out.println("Testing Address -> Port relation");
				sourcePortId = address.select("SocketAddressObj|Port").attr("object_reference");
				String port = doc.select("[id= " + sourcePortId + "] > cybox|Object > cybox|Properties > PortObj|Port_Value").text();
				assertEquals(port, "49870");
			}

			//destination address
			if (!address.select("cybox|Description:contains(6667)").text().isEmpty())	{
				dstAddressID = address.attr("id");
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
				String ip = doc.select("[id= " + destIpId + "] > cybox|Object > cybox|Properties > AddressObj|Address_Value").text();
				assertEquals(ip, "69.42.215.170");

				//dest address -> dest Port
				System.out.println("Testing Address -> Port relation");
				destPortId = address.select("SocketAddressObj|Port").attr("object_reference");
				String port = doc.select("[id= " + destPortId + "] > cybox|Object > cybox|Properties > PortObj|Port_Value").text();
				assertEquals(port, "6667");
			}
		}

		//source IP
		System.out.println();
		System.out.println("Testing Source IP:");
		if (sourceIpId != null)	{
			Element element = doc.select("[id= " + sourceIpId + "]").first();
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
			Element element = doc.select("[id= " + destIpId + "]").first();
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
			Element element = doc.select("[id=" + sourcePortId + "]").first();
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
			Element element = doc.select("[id=" + destPortId + "]").first();
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
		Element flow = doc.select("cybox|Observable:has(cybox|Title:matches(^Flow$))").first();
		String flowID = flow.attr("id");
		System.out.println("Testing Flow:");
		System.out.println("Testing Title");
		assertEquals(flow.select("cybox|Title").text(), "Flow");
		System.out.println("Testing Source");
		assertEquals(flow.select("cyboxCommon|Information_Source_Type").text(), "Hone");
		System.out.println("Testing ID");
		assertEquals(flow.select("cybox|Object").attr("id"), "stucco:flow-169893094_49870-1160435626_6667");
		String srcSocketId = flow.select("NetFlowObj|Src_Socket_Address").attr("object_reference");
		String destSocketId = flow.select("NetFlowObj|Dest_Socket_Address").attr("object_reference");
		Element srcSocket = doc.select("[id=" + srcSocketId + "]").first();
		Element destSocket = doc.select("[id=" + destSocketId + "]").first();

		//hostname -> software relation
		System.out.println("Testing Hostname -> Software relation");
		Element softwareReference = host.select("cybox|Object > cybox|Related_Objects > cybox|Related_Object[idref = " + softwareID + "]").first();
		assertNotNull(softwareReference);

		//hostname -> address relation
		System.out.println("Testing Hostname -> Address relation");
		String addressReference  = host.select("cybox|Object > cybox|Related_Objects > cybox|Related_Object[idref = " + srcAddressID + "]").attr("idref");
		assertNotNull(addressReference);

		//software -> flow relation
		System.out.println("Testing Software -> Flow relation:");
		String flowReference  = software.select("cybox|Object > cybox|Related_Objects > cybox|Related_Object[idref = " + flowID + "]").attr("idref");
		assertNotNull(flowReference);

		//software -> account
		String accountReference  = software.select("cybox|Object > cybox|Related_Objects > cybox|Related_Object[idref = " + accountID + "]").attr("idref");
		assertNotNull(accountReference);

		//flow -> source address
		System.out.println("Testing Flow -> Source Address relation");
		System.out.println("Testing Flow Source IP");
		sourceIpId = srcSocket.select("SocketAddressObj|IP_Address").attr("object_reference");
		String ip = doc.select("[id= " + sourceIpId + "] > cybox|Object > cybox|Properties > AddressObj|Address_Value").text();
		assertEquals(ip, "10.32.92.230");
		System.out.println("Testing Flow Source Port");
		sourcePortId = srcSocket.select("SocketAddressObj|Port").attr("object_reference");
		String port = doc.select("[id= " + sourcePortId + "] > cybox|Object > cybox|Properties > PortObj|Port_Value").text();
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
		assertEquals(flow.select("cybox|Description").text(), "10.32.92.230, port 49870 to 69.42.215.170, port 6667");
		System.out.println("Testing Start Time");
		assertEquals(flow.select("cyboxCommon|Property[name=Start_Time]").text(), "1371797596390");
		System.out.println("Testing Total Packets");
		assertEquals(flow.select("cyboxCommon|Property[name=Total_Packets]").text(), "2");
		System.out.println("Testing Total Bytes");
		assertEquals(flow.select("cyboxCommon|Property[name=Total_Bytes]").text(), "2068");
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
