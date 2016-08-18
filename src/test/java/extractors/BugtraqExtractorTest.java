package STIXExtractor;

import java.util.Map;
import java.util.HashMap;
import java.io.IOException;
import java.nio.charset.Charset;
import java.io.File;
import java.net.URL;
import java.util.List;
import java.util.ArrayList;
import java.util.GregorianCalendar;

import org.jsoup.Jsoup;
import org.jsoup.parser.Parser;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;

import org.junit.Test;

import org.mitre.stix.stix_1.STIXPackage;

import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.DatatypeConfigurationException;
						
import static org.junit.Assert.*;

/**
 * Unit test for simple App.
 */			
public class BugtraqExtractorTest extends STIXUtils {
	
	private Map<String,String> loadContent(int entryNum, boolean localMode) throws IOException {
		Map<String,String> pageContent = new HashMap<String,String>();
		String filePath = "./src/test/resources/bugtraq/";
		Charset charset = Charset.defaultCharset();
		if (localMode) {
			File infoFD = new File(filePath + entryNum + ".info.html");
			String info = FileUtils.readFileToString(infoFD, charset);
			pageContent.put("info", info);
			
			File discussionFD = new File(filePath + entryNum + ".discussion.html");
			String discussion = FileUtils.readFileToString(discussionFD, charset);
			pageContent.put("discussion", discussion);
			
			File exploitFD = new File(filePath + entryNum + ".exploit.html");
			String exploit = FileUtils.readFileToString(exploitFD, charset);
			pageContent.put("exploit", exploit);
			
			File solutionFD = new File(filePath + entryNum + ".solution.html");
			String solution = FileUtils.readFileToString(solutionFD, charset);
			pageContent.put("solution", solution);
			
			File referencesFD = new File(filePath + entryNum + ".references.html");
			String references = FileUtils.readFileToString(referencesFD, charset);
			pageContent.put("references", references);
		}
		else {
			URL u;
			u = new URL("http://www.securityfocus.com/bid/"+entryNum+"/info");
			pageContent.put("info", IOUtils.toString(u));
			
			u = new URL("http://www.securityfocus.com/bid/"+entryNum+"/discussion");
			pageContent.put("discussion", IOUtils.toString(u));
			
			u = new URL("http://www.securityfocus.com/bid/"+entryNum+"/exploit");
			pageContent.put("exploit", IOUtils.toString(u));
			
			u = new URL("http://www.securityfocus.com/bid/"+entryNum+"/solution");
			pageContent.put("solution", IOUtils.toString(u));
			
			u = new URL("http://www.securityfocus.com/bid/"+entryNum+"/references");
			pageContent.put("references", IOUtils.toString(u));
		}
		return pageContent;
	}
	
	/**
	 * Tests conversion for item 2222
	 */
	@Test
	public void testConvert_2222() {
		System.out.println();
		System.out.println("STIXExtractor.BugtraqExtractorTest.testConvert_2222()");

		int entryNum = 2222;
		boolean localMode = true;
		String info, discussion, exploit, solution, references;
		
		try {
			Map<String,String> pageContent = loadContent(entryNum, localMode);
			info = pageContent.get("info");
			discussion = pageContent.get("discussion");
			exploit = pageContent.get("exploit");
			solution = pageContent.get("solution");
			references = pageContent.get("references");
			
			//TODO maybe add a BugtraqExtractor(Map)?
			BugtraqExtractor bugtraqExt = new BugtraqExtractor(info, discussion, exploit, solution, references);
			STIXPackage stixPackage = bugtraqExt.getStixPackage();
						
			System.out.println("Validating StixPackage");
			assertTrue(bugtraqExt.validate(stixPackage));
										
			Document stix = Jsoup.parse(stixPackage.toXMLString(), "", Parser.xmlParser());
			Element et = stix.select("stixCommon|Exploit_Target").first();

			System.out.println("Testing Vulnerability:");
			System.out.println("Testing ID");
			assertEquals(et.select("et|CVE_ID").text(), "");
			System.out.println("Testing Solution");
			assertEquals(stix.select("coa|Description").text(), "Solution: Patches available: SSH Communications Security SSH 1.2.27 SSH Communications SSH1 patch-ssh-1.2.30-secure.rpc http://www.ssh.com/products/ssh/patches/patch-ssh-1.2.30-secure.rpc SSH Communications Security SSH 1.2.28 SSH Communications SSH1 patch-ssh-1.2.30-secure.rpc http://www.ssh.com/products/ssh/patches/patch-ssh-1.2.30-secure.rpc SSH Communications Security SSH 1.2.29 SSH Communications SSH1 patch-ssh-1.2.30-secure.rpc http://www.ssh.com/products/ssh/patches/patch-ssh-1.2.30-secure.rpc SSH Communications Security SSH 1.2.30 SSH Communications SSH1 patch-ssh-1.2.30-secure.rpc http://www.ssh.com/products/ssh/patches/patch-ssh-1.2.30-secure.rpc");
			System.out.println("Testing References");
			assertTrue(et.select("stixCommon|Reference").isEmpty());
			System.out.println("Testing DataBaseID");
			assertEquals(et.select("et|OSVDB_ID").text(), "2222");
			System.out.println("Testing Source");
			assertEquals(et.select("et|Source").text(), "Bugtraq");
			System.out.println("Testing ShortDescription");
			assertEquals(et.select("et|Short_Description").text(), "SSH Secure-RPC Weak Encrypted Authentication Vulnerability");
			System.out.println("Testing Description");
			assertEquals(et.select("et|Description").text(), "SSH Secure-RPC Weak Encrypted Authentication Vulnerability SSH is a package designed to encrypt traffic between two end points using the IETF specified SSH protocol. The SSH1 package is distributed and maintained by SSH Communications Security. A problem exists which could allow the discovery of the secret key used to encrypt traffic on the local host. When using SUN-DES-1 to share keys with other hosts on the network to facilitate secure communication via protocols such as NFS and NIS+, the keys are shared between hosts using the private key of the user and a cryptographic algorithm to secure the contents of the key, which is stored on the NIS+ primary. The problem occurs when the key is encrypted with the SUN-DES-1 magic phrase prior to having done a keylogin (the keyserv does not have the users DH private key). A design flaw in the software that shares the key with the NIS+ master will inconsistently return the correct value for an attempted keyshare that has failed. A step in the private key encryption process is skipped, and the users private key is then encrypted only with the public key of the target server and the SUN-DES-1 magic phrase, a phrase that is guessable due to the way it is generated. A user from the same host can then execute a function that returns another users magic phrase, and use this to decrypt the private key of the victim. This makes it possible for a user with malicious intent to gain knowledge of a users secret key, and decrypt sensitive traffic between two hosts, with the possibility of gaining access and elevated privileges on the hosts and/or NIS+ domain. This reportedly affects the SSH2 series of the software package.");
			System.out.println("Testing PublishedDate");
			GregorianCalendar calendar = new GregorianCalendar();
			calendar.setTimeInMillis(convertTimestamp("Jan 16 2001 12:00AM" + " (GMT)", "MMM dd yyyy hh:mma"));
			assertEquals(et.select("et|Published_DateTime").text(), DatatypeFactory.newInstance().newXMLGregorianCalendar(calendar).toString());
			System.out.println("Testing vulnerability ->  Software");
			Elements vulnSw = stix.select("et|Affected_Software > stixCommon|Observable");
			List<String> stixSw = new ArrayList<String>();
			for (Element sw : vulnSw) {
				stixSw.add(stix.select("cybox|Observable[id=" + sw.attr("idref") + "]").first().select("ProductObj|Product").text());
			}
			assertTrue(stixSw.size() == 4);
			assertTrue(stixSw.contains("SSH Communications Security SSH 1.2.30"));
			assertTrue(stixSw.contains("SSH Communications Security SSH 1.2.29"));
			assertTrue(stixSw.contains("SSH Communications Security SSH 1.2.28"));
			assertTrue(stixSw.contains("SSH Communications Security SSH 1.2.27"));
		} catch (IOException e)	{
			e.printStackTrace();
		} catch (DatatypeConfigurationException e) {
			e.printStackTrace();
		}
	}

	/**
	 * Tests conversion for item 72838
	 */
	@Test
	public void testConvert_72838() {

		System.out.println();
		System.out.println("STIXExtractor.BugtraqExtractorTest.testConvert_72838()");
		int entryNum = 72838;
		boolean localMode = true;
		String info, discussion, exploit, solution, references;
		
		try {
			Map<String,String> pageContent = loadContent(entryNum, localMode);
			info = pageContent.get("info");
			discussion = pageContent.get("discussion");
			exploit = pageContent.get("exploit");
			solution = pageContent.get("solution");
			references = pageContent.get("references");
			
			//TODO maybe add a BugtraqExtractor(Map)?
			BugtraqExtractor bugtraqExt = new BugtraqExtractor(info, discussion, exploit, solution, references);
			STIXPackage stixPackage = bugtraqExt.getStixPackage();
										
			System.out.println("Validating StixPackage");
			assertTrue(bugtraqExt.validate(stixPackage));
										
			Document stix = Jsoup.parse(stixPackage.toXMLString(), "", Parser.xmlParser());
			Element et = stix.select("stixCommon|Exploit_Target").first();

			System.out.println("Testing Vulnerability:");
			System.out.println("Testing ID");
			assertEquals(et.select("et|CVE_ID").text(), "CVE-2015-2098");
			System.out.println("Testing Solution");
			assertEquals(stix.select("coa|Description").text(), "Solution: Currently, we are not aware of any vendor-supplied patches. If you feel we are in error or are aware of more recent information, please mail us at: vuldb@securityfocus.com.");
			System.out.println("Testing References");
			assertEquals(et.select("stixCommon|Reference").first().text(), "http://support.microsoft.com/kb/240797");
			System.out.println("Testing DataBaseID");
			assertEquals(et.select("et|OSVDB_ID").text(), "72838");
			System.out.println("Testing Source");
			assertEquals(et.select("et|Source").text(), "Bugtraq");
			System.out.println("Testing ShortDescription");
			assertEquals(et.select("et|Short_Description").text(), "WebGate eDVR Manager ActiveX Controls CVE-2015-2098 Multiple Buffer Overflow Vulnerabilities");
			System.out.println("Testing Description");
			assertEquals(et.select("et|Description").text(), "WebGate eDVR Manager ActiveX Controls CVE-2015-2098 Multiple Buffer Overflow Vulnerabilities WebGate eDVR Manager is prone to multiple buffer-overflow vulnerabilities because it fails to perform boundary checks before copying user-supplied data to insufficiently sized memory buffer. The controls are identified by CLSID's: 359742AF-BF34-4379-A084-B7BF0E5F34B0 4E14C449-A61A-4BF7-8082-65A91298A6D8 5A216ADB-3009-4211-AB77-F1857A99482C An attacker can exploit these issues to execute arbitrary code in the context of the application, usually Internet Explorer, using the ActiveX control.Failed attacks will likely cause denial-of-service conditions.");
			System.out.println("Testing PublishedDate");
			GregorianCalendar calendar = new GregorianCalendar();
			calendar.setTimeInMillis(convertTimestamp("Mar 27 2015 12:00AM" + " (GMT)", "MMM dd yyyy hh:mma"));
			assertEquals(et.select("et|Published_DateTime").text(), DatatypeFactory.newInstance().newXMLGregorianCalendar(calendar).toString());
			System.out.println("Testing vulnerability ->  Software");
			Elements vulnSw = stix.select("et|Affected_Software > stixCommon|Observable");
			assertTrue(vulnSw.isEmpty());
		} catch (IOException e)	{
			e.printStackTrace();
		} catch (DatatypeConfigurationException e) {
			e.printStackTrace();
		}
	}
}
