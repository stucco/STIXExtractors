package gov.ornl.stucco.stix_extractors;

import gov.ornl.stucco.utils.STIXUtils;

import java.util.List;

import java.io.IOException;

import org.apache.commons.csv.CSVRecord;

import org.jsoup.parser.Parser;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import org.mitre.stix.stix_1.STIXPackage;

import org.xml.sax.SAXException;

import org.junit.Test;

import static org.junit.Assert.*;

/**
 * Unit test for ServiceListExtractor.
 */
public class ServiceListExtractorTest extends STIXUtils {
	
	/**
	 * Test empty document
	 */
	@Test
	public void test_empty_doc() {
			
		System.out.println();
		System.out.println("STIXExtractor.ServiceListExtractor.test_empty_doc()");

		String serviceListInfo = "";

		ServiceListExtractor serviceListExtractor = new ServiceListExtractor(serviceListInfo);
		STIXPackage stixPackage = serviceListExtractor.getStixPackage();

		System.out.println("Testing that STIXPackage is null");
		assertTrue(stixPackage == null);
	}

	/**
	 * Test empty element
	 */
	@Test
	public void test_empty_element() {
			
		System.out.println();
		System.out.println("STIXExtractor.ServerBannerExtractor.test_empty_element()");

		String serviceListInfo = 
			"Service Name,Port Number,Transport Protocol,Description,Assignee,Contact,Registration Date," +
			"Modification Date,Reference,Service Code,Known Unauthorized Uses,Assignment Notes\n" +
			",,,,,,,,,,,,,,";

		ServiceListExtractor serviceListExtractor = new ServiceListExtractor(serviceListInfo);
		STIXPackage stixPackage = serviceListExtractor.getStixPackage();

		System.out.println("Testing that STIXPackage is null");
		assertTrue(stixPackage == null);
	}
	
	/**
	 * Test element with just header
	 */
	@Test
	public void test_element_with_header() {
			
		System.out.println();
		System.out.println("STIXExtractor.ClientBannerExtractor.test_element_with_header()");

		String serviceListInfo = 
			"Service Name,Port Number,Transport Protocol,Description,Assignee,Contact,Registration Date," +
			"Modification Date,Reference,Service Code,Known Unauthorized Uses,Assignment Notes";

		ServiceListExtractor serviceListExtractor = new ServiceListExtractor(serviceListInfo);
		STIXPackage stixPackage = serviceListExtractor.getStixPackage();

		System.out.println("Testing that STIXPackage is null");
		assertTrue(stixPackage == null);
	}

	/**
	 * Test one element
	 */
	@Test
	public void test_one_element_with_header() throws SAXException {
			
		System.out.println();
		System.out.println("STIXExtractor.ServerBannerExtractor.test_one_element_with_header()");

		String serviceListInfo = 
			"Service Name,Port Number,Transport Protocol,Description,Assignee,Contact,Registration Date," +
			"Modification Date,Reference,Service Code,Known Unauthorized Uses,Assignment Notes\n" +
			"ssh,22,tcp,The Secure Shell (SSH) Protocol,,,,,[RFC4251],,,Defined TXT keys: u=<username> p=<password>";

		ServiceListExtractor serviceListExtractor = new ServiceListExtractor(serviceListInfo);
		STIXPackage stixPackage = serviceListExtractor.getStixPackage();

		System.out.println("Validating service_list stixPackage");
		assertTrue(stixPackage.validate());

		Document stixDoc = Jsoup.parse(stixPackage.toXMLString(), "", Parser.xmlParser());		
		Element service = stixDoc.select("cybox|Observable:has(cybox|Title:contains(Service))").first();
		
		System.out.println();
		System.out.println("Testing Service");
		System.out.println("Testing Title");
		assertEquals(service.select("cybox|Title").text(), "Service");
		System.out.println("Testing Source");
		assertEquals(service.select("cyboxCommon|Information_Source_Type").text(), "service_list");
		System.out.println("Testing Name");
		assertEquals(service.select("ProcessObj|Name").text(), "ssh");
		System.out.println("Testing Description");
		assertEquals(service.select("cybox|Description").text(), "The Secure Shell (SSH) Protocol");
		System.out.println("Testing Notes");
		assertEquals(service.select("cyboxCommon|Property[name=Notes]").text(), "Defined TXT keys: u=<username> p=<password>");
		System.out.println("Testing Reference");
		assertEquals(service.select("cyboxCommon|Property[name=Reference]").text(), "[RFC4251]");
		System.out.println("Testing Service -> Port relation");	
		String portId = service.select("ProcessObj|Port").attr("object_reference");
		
		Element port = stixDoc.select("cybox|Observable[id=" + portId + "]").first();

		System.out.println();
		System.out.println("Testing Port");
		System.out.println("Testing Title");
		assertEquals(port.select("cybox|Title").text(), "Port");
		System.out.println("Testing Source");
		assertEquals(port.select("cyboxCommon|Information_Source_Type").text(), "service_list");
		System.out.println("Testing Port value");
		assertEquals(port.select("PortObj|Port_Value").text(), "22");
		System.out.println("Testing Description");
		assertEquals(port.select("cybox|Description").text(), "22");
	}
	
	/**
	 * Test two elements
	 */
	@Test
	public void test_two_elements() throws SAXException {
			
		System.out.println();
		System.out.println("STIXExtractor.ServerBannerExtractor.test_two_elements()");

		String serviceListInfo = 
			"Service Name,Port Number,Transport Protocol,Description,Assignee,Contact,Registration Date," +
			"Modification, Date,Reference,Service Code,Known Unauthorized Uses,Assignment Notes\n" +
			"ssh,22,tcp,The Secure Shell (SSH) Protocol,,,,,[RFC4251],,,Defined TXT keys: u=<username> p=<password>\n" +
			"www-http,80,tcp,World Wide Web HTTP,[Tim_Berners_Lee],[Tim_Berners_Lee],,,,,,\"This is a duplicate of the \"\"http\"\" service and should not be used for discovery purposes." +
      			"u=<username> p=<password> path=<path to document>" +
        		"(see txtrecords.html#http)" +
       	 		"Known Subtypes: _printer" +
        		"NOTE: The meaning of this service type, though called just \"\"http\"\", actually" +
        		"denotes something more precise than just \"\"any data transported using HTTP\"\"." +
        		"The DNS-SD service type \"\"http\"\" should only be used to advertise content that:" +
        		"* is served over HTTP," +
        		"* can be displayed by \"\"typical\"\" web browser client software, and" +
        		"* is intented primarily to be viewed by a human user." +
        		"Of course, the definition of \"\"typical web browser\"\" is subjective, and may" +
        		"change over time, but for practical purposes the DNS-SD service type \"\"http\"\"" +
        		"can be understood as meaning \"\"human-readable HTML content served over HTTP\"\"." +
        		"In some cases other widely-supported content types may also be appropriate," +
        		"such as plain text over HTTP, or JPEG image over HTTP." +
        		"Content types not intented primarily for viewing by a human user, or not" +
        		"widely-supported in web browsing clients, should not be advertised as" +
        		"DNS-SD service type \"\"http\"\", even if they do happen to be transported over HTTP." +
        		"Such types should be advertised as their own logical service type with their" +
        		"own DNS-SD service type, for example, XUL (XML User Interface Language)" +
        		"transported over HTTP is advertised explicitly as DNS-SD service type \"\"xul-http\"\".\"\n" +
			"login,513,tcp,\"remote login a la telnet; automatic authentication performed based on priviledged port numbers and distributed data bases which identify" +
			"\"\"authentication domains\"\" \",,,,,,,,\n" +
			"who,513,udp,maintains data bases showing who's logged in to machines on a local net and the load average of the machine,,,,,,,,\n" +
			"sms,,,Short Text Message Sending and Delivery Status Service,[Christian_Flintrup],[Christian_Flintrup],,,,,,Defined TXT keys: Proprietary";

		ServiceListExtractor serviceListExtractor = new ServiceListExtractor(serviceListInfo);
		STIXPackage stixPackage = serviceListExtractor.getStixPackage();

		System.out.println("Validating service_list stixPackage");
		assertTrue(stixPackage.validate());

		Document stixDoc = Jsoup.parse(stixPackage.toXMLString(), "", Parser.xmlParser());		
		Element service = stixDoc.select("cybox|Observable:has(ProcessObj|Name:contains(ssh))").first();
		
		System.out.println();
		System.out.println("Testing Service");
		System.out.println("Testing Title");
		assertEquals(service.select("cybox|Title").text(), "Service");
		System.out.println("Testing Source");
		assertEquals(service.select("cyboxCommon|Information_Source_Type").text(), "service_list");
		System.out.println("Testing Name");
		assertEquals(service.select("ProcessObj|Name").text(), "ssh");
		System.out.println("Testing Description");
		assertEquals(service.select("cybox|Description").text(), "The Secure Shell (SSH) Protocol");
		System.out.println("Testing Notes");
		assertEquals(service.select("cyboxCommon|Property[name=Notes]").text(), "Defined TXT keys: u=<username> p=<password>");
		System.out.println("Testing Reference");
		assertEquals(service.select("cyboxCommon|Property[name=Reference]").text(), "[RFC4251]");
		System.out.println("Testing Service -> Port relation");	
		String portId = service.select("ProcessObj|Port").attr("object_reference");
		
		Element port = stixDoc.select("cybox|Observable[id=" + portId + "]").first();

		System.out.println();
		System.out.println("Testing Port");
		System.out.println("Testing Title");
		assertEquals(port.select("cybox|Title").text(), "Port");
		System.out.println("Testing Source");
		assertEquals(port.select("cyboxCommon|Information_Source_Type").text(), "service_list");
		System.out.println("Testing Port value");
		assertEquals(port.select("PortObj|Port_Value").text(), "22");
		System.out.println("Testing Description");
		assertEquals(port.select("cybox|Description").text(), "22");
		
		service = stixDoc.select("cybox|Observable:has(ProcessObj|Name:contains(www-http))").first();
		
		System.out.println();
		System.out.println("Testing Service");
		System.out.println("Testing Title");
		assertEquals(service.select("cybox|Title").text(), "Service");
		System.out.println("Testing Source");
		assertEquals(service.select("cyboxCommon|Information_Source_Type").text(), "service_list");
		System.out.println("Testing Name");
		assertEquals(service.select("ProcessObj|Name").text(), "www-http");
		System.out.println("Testing Description");
		assertEquals(service.select("cybox|Description").text(), "World Wide Web HTTP");
		System.out.println("Testing Notes");
		assertEquals(service.select("cyboxCommon|Property[name=Notes]").text(), "This is a duplicate of the \"http\" service and should not be used for discovery purposes.u=<username> p=<password> path=<path to document>(see txtrecords.html#http)Known Subtypes: _printerNOTE: The meaning of this service type, though called just \"http\", actuallydenotes something more precise than just \"any data transported using HTTP\".The DNS-SD service type \"http\" should only be used to advertise content that:* is served over HTTP,* can be displayed by \"typical\" web browser client software, and* is intented primarily to be viewed by a human user.Of course, the definition of \"typical web browser\" is subjective, and maychange over time, but for practical purposes the DNS-SD service type \"http\"can be understood as meaning \"human-readable HTML content served over HTTP\".In some cases other widely-supported content types may also be appropriate,such as plain text over HTTP, or JPEG image over HTTP.Content types not intented primarily for viewing by a human user, or notwidely-supported in web browsing clients, should not be advertised asDNS-SD service type \"http\", even if they do happen to be transported over HTTP.Such types should be advertised as their own logical service type with theirown DNS-SD service type, for example, XUL (XML User Interface Language)transported over HTTP is advertised explicitly as DNS-SD service type \"xul-http\".");
		System.out.println("Testing Reference");
		assertEquals(service.select("cyboxCommon|Property[name=Reference]").text(), "");
		System.out.println("Testing Service -> Port relation");	
		portId = service.select("ProcessObj|Port").attr("object_reference");
		
		port = stixDoc.select("cybox|Observable[id=" + portId + "]").first();

		System.out.println();
		System.out.println("Testing Port");
		System.out.println("Testing Title");
		assertEquals(port.select("cybox|Title").text(), "Port");
		System.out.println("Testing Source");
		assertEquals(port.select("cyboxCommon|Information_Source_Type").text(), "service_list");
		System.out.println("Testing Port value");
		assertEquals(port.select("PortObj|Port_Value").text(), "80");
		System.out.println("Testing Description");
		assertEquals(port.select("cybox|Description").text(), "80");
		
		service = stixDoc.select("cybox|Observable:has(ProcessObj|Name:contains(login))").first();
		
		System.out.println();
		System.out.println("Testing Service");
		System.out.println("Testing Title");
		assertEquals(service.select("cybox|Title").text(), "Service");
		System.out.println("Testing Source");
		assertEquals(service.select("cyboxCommon|Information_Source_Type").text(), "service_list");
		System.out.println("Testing Name");
		assertEquals(service.select("ProcessObj|Name").text(), "login");
		System.out.println("Testing Description");
		assertEquals(service.select("cybox|Description").text(), "remote login a la telnet; automatic authentication performed based on priviledged port numbers and distributed data bases which identify\"authentication domains\"");
		System.out.println("Testing Notes");
		assertEquals(service.select("cyboxCommon|Property[name=Notes]").text(), "");
		System.out.println("Testing Reference");
		assertEquals(service.select("cyboxCommon|Property[name=Reference]").text(), "");
		System.out.println("Testing Service -> Port relation");	
		portId = service.select("ProcessObj|Port").attr("object_reference");
		
		port = stixDoc.select("cybox|Observable[id=" + portId + "]").first();

		System.out.println();
		System.out.println("Testing Port");
		System.out.println("Testing Title");
		assertEquals(port.select("cybox|Title").text(), "Port");
		System.out.println("Testing Source");
		assertEquals(port.select("cyboxCommon|Information_Source_Type").text(), "service_list");
		System.out.println("Testing Port value");
		assertEquals(port.select("PortObj|Port_Value").text(), "513");
		System.out.println("Testing Description");
		assertEquals(port.select("cybox|Description").text(), "513");
		
		service = stixDoc.select("cybox|Observable:has(ProcessObj|Name:contains(who))").first();
		
		System.out.println();
		System.out.println("Testing Service");
		System.out.println("Testing Title");
		assertEquals(service.select("cybox|Title").text(), "Service");
		System.out.println("Testing Source");
		assertEquals(service.select("cyboxCommon|Information_Source_Type").text(), "service_list");
		System.out.println("Testing Name");
		assertEquals(service.select("ProcessObj|Name").text(), "who");
		System.out.println("Testing Description");
		assertEquals(service.select("cybox|Description").text(), "maintains data bases showing who's logged in to machines on a local net and the load average of the machine");
		System.out.println("Testing Notes");
		assertEquals(service.select("cyboxCommon|Property[name=Notes]").text(), "");
		System.out.println("Testing Reference");
		assertEquals(service.select("cyboxCommon|Property[name=Reference]").text(), "");
		System.out.println("Testing Service -> Port relation");	
		portId = service.select("ProcessObj|Port").attr("object_reference");
		
		port = stixDoc.select("cybox|Observable[id=" + portId + "]").first();

		System.out.println();
		System.out.println("Testing Port");
		System.out.println("Testing Title");
		assertEquals(port.select("cybox|Title").text(), "Port");
		System.out.println("Testing Source");
		assertEquals(port.select("cyboxCommon|Information_Source_Type").text(), "service_list");
		System.out.println("Testing Port value");
		assertEquals(port.select("PortObj|Port_Value").text(), "513");
		System.out.println("Testing Description");
		assertEquals(port.select("cybox|Description").text(), "513");
	}
}	
