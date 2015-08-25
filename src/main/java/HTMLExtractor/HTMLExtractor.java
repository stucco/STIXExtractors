package STIXExtractor;

import javax.xml.namespace.QName;

import java.util.UUID;
import java.util.Iterator;
import java.util.GregorianCalendar;
import java.util.TimeZone;
import java.util.Date;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import java.io.File;
import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.io.IOException;

import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;

import java.nio.charset.Charset;

import java.text.ParseException;
import java.text.SimpleDateFormat;

import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVRecord;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;

import org.json.*;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Attributes;
import org.jsoup.nodes.Element;
import org.jsoup.parser.Tag;
import org.jsoup.select.Elements;

import org.mitre.stix.stix_1.STIXPackage;
import org.mitre.stix.stix_1.STIXHeaderType;
import org.mitre.stix.common_1.ControlledVocabularyStringType;
import org.mitre.cybox.common_2.AnyURIObjectPropertyType;
import org.mitre.cybox.common_2.MeasureSourceType;	
import org.mitre.cybox.common_2.StringObjectPropertyType;
import org.mitre.cybox.common_2.HashType;
import org.mitre.cybox.common_2.SimpleHashValueType;
import org.mitre.cybox.common_2.PositiveIntegerObjectPropertyType;
import org.mitre.cybox.common_2.StructuredTextType;
import org.mitre.cybox.cybox_2.Observables;
import org.mitre.cybox.cybox_2.RelatedObjectType;
import org.mitre.cybox.cybox_2.Observable;
import org.mitre.cybox.cybox_2.ObjectType;
import org.mitre.cybox.cybox_2.KeywordsType;
import org.mitre.cybox.objects.URIObjectType;
import org.mitre.cybox.objects.Address;
import org.mitre.cybox.objects.CategoryTypeEnum;
import org.mitre.cybox.objects.NetworkFlowObject;
import org.mitre.cybox.objects.NetworkFlowLabelType;
import org.mitre.cybox.objects.IANAAssignedIPNumbersType;
import org.mitre.cybox.objects.IANAAssignedIPNumbersTypeEnum;
import org.mitre.cybox.objects.Hostname;
import org.mitre.cybox.objects.Port;
import org.mitre.cybox.objects.SocketAddress;
import org.mitre.cybox.objects.WhoisEntry;
import org.mitre.cybox.objects.UserAccountObjectType;
import org.mitre.cybox.objects.Product;
import org.mitre.stix.ttp_1.MalwareInstanceType;
import org.mitre.stix.ttp_1.TTP;
import org.mitre.stix.common_1.IdentityType;
import org.mitre.stix.common_1.InformationSourceType;
import org.mitre.cybox.common_2.ConditionTypeEnum;
import org.mitre.cybox.common_2.ConditionApplicationEnum;

import org.xml.sax.SAXException;

public abstract class HTMLExtractor {

	private static final int MAX_COMPARE_DEPTH = 8;
	private static final boolean DEBUG_COMPARE = false;
	
	protected static String findWithRegex(String content, String regex){
		return findWithRegex(content, regex, 1);
	}
	
	protected static String findWithRegex(String content, String regex, int groupNum){
		Pattern pattern = Pattern.compile(regex);
	    	Matcher matcher = pattern.matcher(content);
	    	matcher.find();
		return matcher.group(1);
	}

	protected static void trimAll(String[] items) {
		for(int i=0; i<items.length; i++){
	    	items[i] = items[i].trim();
	    }
	}
	
	protected static boolean isEmpty(String content)	{

		if (content.length() == 0)
			return true;
		else
			return false;
	}

	protected static void removeBRs(Elements contents){
		Element curr;
		for(int i = contents.size()-1; i>=0; i--){
			curr = contents.get(i);
			if(curr.tagName().equals("br")){
				contents.remove(i);
				continue;
			}
		}
	}
	
	protected static void removeHRs(Elements contents){
		Element curr;
		for(int i = contents.size()-1; i>=0; i--){
			curr = contents.get(i);
			if(curr.tagName().equals("hr")){
				contents.remove(i);
				continue;
			}
		}
	}
	
	//NB: assumes dt and dd are one-to-one (will skip ones that aren't)
	//NB: also assumes that dt and dd tags have text()-able content.
	protected Map<String, String> dlToMap(Element dl) {
		HashMap<String, String> retMap = new HashMap<String, String>();
		if( dl.tagName().equals("dl") ){
			Elements terms = dl.getElementsByTag("dt");
			Element currTerm, currDef;
			for(int i=0; i<terms.size(); i++){
				currTerm = terms.get(i);
				currDef = currTerm.nextElementSibling();
				if(currDef != null && currDef.tagName().equals("dd")){
					retMap.put(currTerm.text(), currDef.text());
				}
			}
			return retMap;	
		}
		else return null;
	}
	
	//NB: assumes that the li tags have (cleanly) text()-able content.
	protected Set<String> ulToSet(Element ul) {
		TreeSet<String> retSet = new TreeSet<String>();
		if( ul.tagName().equals("ul") ){
			Elements items = ul.getElementsByTag("li");
			Element currItem;
			for(int i=0; i<items.size(); i++){
				currItem = items.get(i);
				retSet.add(currItem.text());
			}
			return retSet;
		}
		else return null;
	}
	
	//NB: this will leave some empty grandchild-level tags around, but children will still be cleanly text()-able
	//TODO: revisit above.
	protected Element removeGrandchildren(Element parent) {
		Elements children = parent.children();
		Elements grandchildren;
		for(int i=0; i<children.size(); i++){
			grandchildren = children.get(i).children();
			for(int j=0; j<grandchildren.size(); j++){
				grandchildren.get(j).empty();
			}
		}
		return parent;
	}
	
	//NB: JSON array must be array of strings
	protected Set<String> JSONArrayToSet(JSONArray arr) {
		TreeSet<String> retSet = new TreeSet<String>();
		if(arr != null){
			for(int i=0; i<arr.length(); i++){
				retSet.add(arr.getString(i));
			}
		}
		return retSet;
	}
	
	protected long convertTimestamp(String time, String format)	{ 
		Date date = new Date();
		try {
			SimpleDateFormat df = new SimpleDateFormat(format);
  			date = df.parse(time);
  			return date.getTime();	

		} catch	(ParseException e)	{
			e.printStackTrace();
		}
  		return date.getTime();	
	}
	
	protected ArrayList<String> findAllLinkHrefs(Element content) {
		Elements refs = content.select("a[href]");
		ArrayList<String> hrefStrings = new ArrayList<String>();
		String hrefString = "";
		for(int i=0; i<refs.size(); i++){
			hrefString = refs.get(i).attr("href");
			hrefStrings.add(hrefString);
		}
		//System.out.println(refs);
		//System.out.println(refStrings);
		return hrefStrings;
	}
	
	/*
	 * Get 2d array of cell contents, from a list of tr elements
	 */
	protected String[][] getCells(Elements rows) {
		int rowCount = rows.size();
		int colCount = rows.first().getElementsByTag("td").size();
		//System.out.println(rowCount + " rows, by " + colCount + " cols");
		
		String[][] contents = new String[rowCount][colCount];
		Element currCell, currChild;
		String currCellText;
		
		for(int i=0; i<rowCount; i++){
			for(int j=0; j<colCount; j++){
				currCell = rows.get(i).getElementsByTag("td").get(j);
				currCellText = currCell.text();
				if(currCellText.equals("")){ //if you haven't found text yet, try harder.
					if(currCell.childNodeSize() != 0){ //...if you can.
						currChild = currCell.child(0);
						if(currChild.tagName().equals("img")){
							currCellText = currChild.attr("title");
						}
						//TODO handle other cases as they arise.
					}
				}
				//System.out.println(currCellText);
				contents[i][j] = currCellText;
			}
		}
		return contents;
	}
	
	protected static String getDomainFromURL(String url) throws URISyntaxException {
	    URI uri = new URI(url);
	    return uri.getHost();
	}
	
	protected static int getPortFromURL(String url) throws URISyntaxException {
		URI uri;
		int port;
		if(!url.contains("://")){ //if no protocol specified, assume http
			url = "http://" + url;
		}
		uri = new URI(url);
	    port = uri.getPort();
		//handle default ports for well known protocols
		if(port == -1 && url.startsWith("http://")){
			port = 80;
		}
		else if(port == -1 && url.startsWith("https://")){
			port = 443;
		}//TODO add more defaults as needed
	    return port;
	}
	
	public static boolean deepCompareJSONObjects(JSONObject obj1, JSONObject obj2){
		return deepCompareJSONObjects(obj1, obj2, 0, true);
	}
	
	public static boolean deepCompareJSONObjectsUnordered(JSONObject obj1, JSONObject obj2){
		return deepCompareJSONObjects(obj1, obj2, 0, false);
	}
	
	private static boolean deepCompareJSONObjects(JSONObject obj1, JSONObject obj2, int currDepth, boolean ordered){
		boolean retVal = true;
		//System.out.println("depth: " + currDepth);
		if(currDepth <= MAX_COMPARE_DEPTH){
			Set<String> obj1keys = obj1.keySet();
			Set<String> obj2keys = obj2.keySet();
			if(obj1keys.equals(obj2keys)){
				for(String k : obj1keys){
					if(!retVal) continue;
					//check if an obj...
					JSONObject o1 = obj1.optJSONObject(k);
					JSONObject o2 = obj2.optJSONObject(k);
					if(o1 != null && o2 != null){
						retVal = retVal && deepCompareJSONObjects(o1, o2, currDepth+1, ordered);
						if(!retVal && DEBUG_COMPARE) System.out.println("JSON Object compare failed on key " + k + " (object)");
						continue;
					}
					
					//or try as an array...
					JSONArray a1 = obj1.optJSONArray(k);
					JSONArray a2 = obj2.optJSONArray(k);
					if(a1 != null && a2 != null){
						if(ordered)
							retVal = retVal && deepCompareJSONArrays(a1, a2, currDepth+1);
						else
							retVal = retVal && deepCompareJSONArraysUnordered(a1, a2, currDepth+1);
						if(!retVal && DEBUG_COMPARE) System.out.println("JSON Object compare failed on key " + k + " (array)");
						continue;
					}
					
					//or just get as strings and compare
					String s1 = obj1.optString(k);
					String s2 = obj2.optString(k);
					retVal = retVal && s1.equals(s2);
					if(!retVal && DEBUG_COMPARE) System.out.println("JSON Object compare failed on key " + k + " (other type)");
				}
			}
			else{//keys don't match, so fail.
				if(DEBUG_COMPARE) System.out.println("JSON Object compare failed because key sets do not match");
				retVal = false;
			}
		}
		else{//over the limit, so fail.
			if(DEBUG_COMPARE) System.out.println("JSON Object compare failed because depth limit exceeded");
			retVal = false;
		}
		return retVal;
	}
	
	public static boolean deepCompareJSONArrays(JSONArray arr1, JSONArray arr2){
		return deepCompareJSONArrays(arr1, arr2, 0);
	}
	
	private static boolean deepCompareJSONArrays(JSONArray arr1, JSONArray arr2, int currDepth){
		boolean retVal = true;
		//System.out.println("depth: " + currDepth);
		if(currDepth <= MAX_COMPARE_DEPTH){
			if(arr1.length() == arr2.length()){
				for(int i=0; i<arr1.length() && retVal; i++){
					//check if an obj...
					JSONObject o1 = arr1.optJSONObject(i);
					JSONObject o2 = arr2.optJSONObject(i);
					if(o1 != null && o2 != null){
						retVal = retVal && deepCompareJSONObjects(o1, o2, currDepth+1, true);
						if(!retVal && DEBUG_COMPARE) System.out.println("JSON Array compare failed on index " + i + " (object)");
						continue;
					}
					
					//or try as an array...
					JSONArray a1 = arr1.optJSONArray(i);
					JSONArray a2 = arr2.optJSONArray(i);
					if(a1 != null && a2 != null){
						retVal = retVal && deepCompareJSONArrays(a1, a2, currDepth+1);
						if(!retVal && DEBUG_COMPARE) System.out.println("JSON Array compare failed on index " + i + " (array)");
						continue;
					}
					
					//or just get as strings and compare
					String s1 = arr1.optString(i);
					String s2 = arr2.optString(i);
					retVal = retVal && s1.equals(s2);
					if(!retVal && DEBUG_COMPARE) System.out.println("JSON Array compare failed on index " + i + " (other type)");
				}
			}
			else{//length doesn't match, so fail.
				if(DEBUG_COMPARE) System.out.println("JSON Array compare failed because of differing lengths");
				retVal = false;
			}
		}
		else{//over the limit, so fail.
			if(DEBUG_COMPARE) System.out.println("JSON Array compare failed because depth limit exceeded");
			retVal = false;
		}
		return retVal;
	}
	
	public static boolean deepCompareJSONArraysUnordered(JSONArray arr1, JSONArray arr2){
		return deepCompareJSONArraysUnordered(arr1, arr2, 0);
	}
	
	private static boolean deepCompareJSONArraysUnordered(JSONArray arr1, JSONArray arr2, int currDepth){
		boolean retVal = true;
		//System.out.println("depth: " + currDepth);
		if(currDepth <= MAX_COMPARE_DEPTH){
			if(arr1.length() == arr2.length()){
				/*
				HashSet<Object> set1 = new HashSet<Object>();
				HashSet<Object> set2 = new HashSet<Object>();
				for(int i=arr1.length()-1; i>=0; i--){
					set1.add( arr1.remove(i) );
					set2.add( arr2.remove(i) );
				}
				*/
				for(int i=0; i<arr1.length() && retVal; i++){
					boolean itemMatched = false;
					for(int j=0; j<arr2.length() && !itemMatched; j++){
						//check if an obj...
						JSONObject o1 = arr1.optJSONObject(i);
						JSONObject o2 = arr2.optJSONObject(j);
						if(o1 != null && o2 != null){
							itemMatched = retVal && deepCompareJSONObjects(o1, o2, currDepth+1, false);
							//if(!retVal && DEBUG_COMPARE) System.out.println("JSON Array compare failed on index " + i + " (object)");
							continue;
						}
						
						//or try as an array...
						JSONArray a1 = arr1.optJSONArray(i);
						JSONArray a2 = arr2.optJSONArray(j);
						if(a1 != null && a2 != null){
							itemMatched = retVal && deepCompareJSONArraysUnordered(a1, a2, currDepth+1);
							//if(!retVal && DEBUG_COMPARE) System.out.println("JSON Array compare failed on index " + i + " (array)");
							continue;
						}
						
						//or just get as strings and compare
						String s1 = arr1.optString(i);
						String s2 = arr2.optString(j);
						itemMatched = retVal && s1.equals(s2);
						//if(!retVal && DEBUG_COMPARE) System.out.println("JSON Array compare failed on index " + i + " (other type)");
					}
					retVal = itemMatched;
					if(!retVal && DEBUG_COMPARE) System.out.println("JSON Array compare failed on index " + i);
				}
			}
			else{//length doesn't match, so fail.
				if(DEBUG_COMPARE) System.out.println("JSON Array compare failed because of differing lengths");
				retVal = false;
			}
		}
		else{//over the limit, so fail.
			if(DEBUG_COMPARE) System.out.println("JSON Array compare failed because depth limit exceeded");
			retVal = false;
		}
		return retVal;
	}

	public static boolean compareStixPackages (STIXPackage package1, STIXPackage package2)	{
									
		JSONObject object1 = XML.toJSONObject(package1.toXMLString());
		JSONObject object2 = XML.toJSONObject(package2.toXMLString());
			
		return compareJSONObjects (object1, object2);
	}
		
	public static boolean compareJSONObjects (JSONObject object1, JSONObject object2)	{

		if (object1 == null && object2 != null) return false;
		if (object1 != null && object2 == null) return false;			

		List<String> keysArray1 = new ArrayList<String>();
		List<String> keysArray2 = new ArrayList<String>();

		Iterator<String> keys1 = object1.keys();
		while(keys1.hasNext())	
			keysArray1.add(keys1.next());
		
		Iterator<String> keys2 = object2.keys();
		while(keys2.hasNext())	
			keysArray2.add(keys2.next());
									
		if (keysArray1.size() != keysArray2.size())	return false;
					
		keysArray1.remove("id");
		keysArray1.remove("idref");
		keysArray1.remove("timestamp");		
		keysArray2.remove("id");
		keysArray2.remove("idref");
		keysArray2.remove("timestamp");		
				
		for (String key: keysArray1)	{
			if (!object2.has(key)) return false; 
		}

		for (int i = 0; i < keysArray1.size(); i++)	{
			String key = keysArray1.get(i);
			if (compare(object1.get(key), object2.get(key)) == false) return false;
		}
						
		return true;
	}
						
	public static boolean compareJSONArrays(JSONArray array1, JSONArray array2)	{
		
		if (array1 == null && array2 != null) return false;
		if (array1 != null && array2 == null) return false;			
		if (array1.length() != array2.length())	return false;

		for (int i = 0; i < array1.length(); i++)	{
			Object o1 = array1.get(i);
			boolean equals = false;
			for (int j = 0; j < array2.length(); j++)	{
				Object o2 = array2.get(j);
				equals = compare(o1, o2);
				if (equals == true) break;
			}
			if (equals == false)	return false;
		}
		return true;

	}
			
	public static boolean compare	(Object object1, Object object2)	{
									
		if (object1 instanceof JSONArray && object2  instanceof JSONArray)	
			return compareJSONArrays((JSONArray)object1, (JSONArray)object2);
																		
		else if (object1 instanceof JSONObject && object2 instanceof JSONObject)	
			return compareJSONObjects((JSONObject)object1, (JSONObject)object2);
		
		else	return object1.toString().equals(object2.toString());
	}


	public List getCSVRecordsList (String[] HEADERS, String info)	throws IOException	{

		CSVFormat csvFormat = CSVFormat.DEFAULT.withHeader(HEADERS);
		Reader reader = new StringReader(info);
		CSVParser csvParser = new CSVParser(reader, csvFormat);

		return  csvParser.getRecords();
	}

	public STIXPackage initStixPackage (String source) throws DatatypeConfigurationException	{
	
		GregorianCalendar calendar = new GregorianCalendar();
		XMLGregorianCalendar now = DatatypeFactory.newInstance().newXMLGregorianCalendar(				
			new GregorianCalendar(TimeZone.getTimeZone("UTC")));

		return new STIXPackage()				
 			.withSTIXHeader(new STIXHeaderType()
				.withTitle(source)) 
			.withTimestamp(now)
 			.withId(new QName("gov.ornl.stucco", source + "-" + UUID.randomUUID().toString(), "stucco"));
	}

	public Observables initObservables ()	{
		
		return new Observables()
			.withCyboxMajorVersion("2.0")
			.withCyboxMinorVersion("1.0");
	}

	public TTP initTTP(String source) {
		return new TTP()
			.withId(new QName("gov.ornl.stucco", "malware-" + UUID.randomUUID().toString(), "stucco"))
			.withTitle("Malware")
			.withInformationSource(new InformationSourceType()
				.withIdentity(new IdentityType()
					.withName(source)));
	}

	public Observable initFlowObservable (String source) {
		
		return new Observable()
			.withId(new QName("gov.ornl.stucco", "flow-" + UUID.randomUUID().toString(), "stucco"))
			.withTitle("Flow")
			.withObservableSources(getMeasureSourceType("Argus"));
	}

     	public URIObjectType setURIObjectType (String uri)	{
	
     		return new URIObjectType()
        		.withValue(new AnyURIObjectPropertyType()
                		.withValue(uri));
	}

     	public URIObjectType getURIObjectType (String uri)	{
	
     		return new URIObjectType()
        		.withValue(new AnyURIObjectPropertyType()
                		.withValue(uri));
	}
	
	public MeasureSourceType setMeasureSourceType (String source)	{
	
		return new MeasureSourceType()
                	.withInformationSourceType(new org.mitre.cybox.common_2.ControlledVocabularyStringType()
	                     	.withValue(source));
	}

	public MeasureSourceType getMeasureSourceType (String source)	{
	
		return new MeasureSourceType()
                	.withInformationSourceType(new org.mitre.cybox.common_2.ControlledVocabularyStringType()
	                     	.withValue(source));
	}

	public HashType setHashType (String hash, String type)	{

		return new HashType()	
			.withType(new org.mitre.cybox.common_2.ControlledVocabularyStringType()
				.withValue(type))
			.withSimpleHashValue(new SimpleHashValueType()
				.withValue(hash));
	}

	public RelatedObjectType setRelatedObjectType (QName idref, String relationship)	{

   		return new RelatedObjectType()
                   		.withIdref(idref)
                     		.withRelationship(new org.mitre.cybox.common_2.ControlledVocabularyStringType()
                           	.withValue(relationship));
	}

	public Observable setHostObservable (String hostname, String source)	{

		return new Observable()
			.withId(new QName("gov.ornl.stucco", "hostname-" + UUID.randomUUID().toString(), "stucco"))
	            	.withTitle("Host")
                	.withObservableSources(getMeasureSourceType(source))
                      	.withObject(new ObjectType()
                    		.withId(new QName("gov.ornl.stucco", "hostname-" + hostname, "stucco"))
                                .withDescription(new StructuredTextType()
                      			.withValue(hostname))
                           	.withProperties(new Hostname()
                                	.withHostnameValue(new StringObjectPropertyType()
                                       		.withValue(hostname))));
	}

	public Observable setAddressObservable (String ip, long ipInt, QName ipId, String port, QName portId, String source)	{

		return new Observable()
				.withId(new QName("gov.ornl.stucco", "address-" + UUID.randomUUID().toString(), "stucco"))	
				.withTitle("Address")
				.withObservableSources(getMeasureSourceType(source))
				.withObject(new ObjectType()
					.withId(new QName("gov.ornl.stucco", "address-" + ipToLong(ip) + "_" + port, "stucco"))
					.withDescription(new org.mitre.cybox.common_2.StructuredTextType()
						.withValue(ip + ", port " + port)) 
					.withProperties(new SocketAddress()
						.withIPAddress(new Address()
							.withObjectReference(ipId))
						.withPort(new Port()
							.withObjectReference(portId))));
	}

	public Observable setAddressRangeObservable(String startIp, String endIp, String source) {
		return setAddressRangeObservable(startIp, endIp, startIp + " through " + endIp, source);
	}
	
	public Observable setAddressRangeObservable(String startIp, String endIp, String description, String source) {
		return new Observable()
			.withId(new QName("gov.ornl.stucco", "addressRange-" + UUID.randomUUID().toString(), "stucco"))
			.withTitle("AddressRange")
			.withObservableSources(getMeasureSourceType(source))
			.withObject(new ObjectType()
				.withId(new QName("gov.ornl.stucco", "addressRange-" + ipToLong(startIp) + "-" + ipToLong(endIp), "stucco"))
				.withDescription(new org.mitre.cybox.common_2.StructuredTextType()
					.withValue(description))
				.withProperties(new Address()
					.withAddressValue(new StringObjectPropertyType()
						.withValue(startIp + " - " + endIp)
					.withCondition(ConditionTypeEnum.INCLUSIVE_BETWEEN)
					.withApplyCondition(ConditionApplicationEnum.ANY)
					.withDelimiter(" - "))
					.withCategory(CategoryTypeEnum.IPV_4_ADDR)));
	}

	//TODO Remove later
	public Observable getAddressObservable (String ip, QName ipId, String port, QName portId, String source)	{

		return new Observable()
				.withId(new QName("gov.ornl.stucco", "address-" + UUID.randomUUID().toString(), "stucco"))	
				.withTitle("Address")
				.withObservableSources(getMeasureSourceType(source))
				.withObject(new ObjectType()
					.withId(new QName("gov.ornl.stucco", "address-" + ipToLong(ip) + "_" + port, "stucco"))
					.withDescription(new org.mitre.cybox.common_2.StructuredTextType()
						.withValue(ip + ", port " + port)) 
					.withProperties(new SocketAddress()
						.withIPAddress(new Address()
							.withObjectReference(ipId))
						.withPort(new Port()
							.withObjectReference(portId))));
	}

	//TODO remove later
/*	public Observable getAddressObservable (String source, String ip, String port,  CategoryTypeEnum category)	{

		QName addressId = new QName("gov.ornl.stucco", "address-" + UUID.randomUUID().toString(), "stucco");	
		String address  = ip  + ":" + port;
															
		return new Observable()
				.withId(addressId)
				.withTitle("Address")
				.withObservableSources(getMeasureSourceType(source))
				.withObject(new ObjectType()
					.withId(new QName("gov.ornl.stucco", "address-" + ip + "-" + port, "stucco"))
					.withDescription(new org.mitre.cybox.common_2.StructuredTextType()
						.withValue(ip + ", port " + port)) 
					.withProperties(new SocketAddress()
						.withPort(new Port()
							.withPortValue(new PositiveIntegerObjectPropertyType()
                                            			.withValue(port)))
						.withIPAddress(getAddress(ip, category))));
	}
*/
	
	public Observable setIpObservable (String ip, long ipInt, String keyword, String source)	{

		return setIpObservable(ip, ipInt, source)
			.withKeywords(new KeywordsType()
		                .withKeywords(keyword));
	}
	
	public Observable setIpObservable (String ip, String source)	{

		return setIpObservable(ip, ipToLong(ip), source);
	}	

	public Observable setIpObservable (String ip, long ipLong, String source)	{

		return new Observable()
				.withId(new QName("gov.ornl.stucco", "ip-" + UUID.randomUUID().toString(), "stucco"))	
				.withTitle("IP")
				.withObservableSources(getMeasureSourceType(source))
				.withObject(new ObjectType()
					.withId(new QName("gov.ornl.stucco", "ip-" + ipLong, "stucco"))
					.withDescription(new org.mitre.cybox.common_2.StructuredTextType()
						.withValue(ip)) 
					.withProperties(setAddress(ip, CategoryTypeEnum.IPV_4_ADDR)));
	}

	public long ipToLong(String ipString)	{

		long ipLong = 0;
		long ip;
		String[] ipArray = ipString.split("\\.");

		for (int i = 3; i >= 0; i--) {
			ip = Long.parseLong(ipArray[3 - i]);
			ipLong |= ip << (i * 8);
		}
		
		return ipLong;
	}
	
	public Address setAddress (String address)	{
	
		return new Address()
			.withAddressValue(new StringObjectPropertyType()
				.withValue(address));
	}

	public Address setAddress (String address, CategoryTypeEnum category)	{
	
		return new Address()
			.withAddressValue(new StringObjectPropertyType()
				.withValue(address))
			.withCategory(category);
	}

	//TODO remove later
	public Observable getIpObservable (String source, String ip, CategoryTypeEnum category)	{

		QName ipId = new QName("gov.ornl.stucco", "ip-" + UUID.randomUUID().toString(), "stucco");	

		return new Observable()
				.withId(ipId)
				.withTitle("IP")
				.withObservableSources(getMeasureSourceType(source))
				.withObject(new ObjectType()
					.withId(new QName("gov.ornl.stucco", "ip-" + ip, "stucco"))
					.withDescription(new org.mitre.cybox.common_2.StructuredTextType()
						.withValue(ip)) 
					.withProperties(setAddress(ip, category)));
	}

	public Observable setPortObservable (String port, String source)	{

		QName portId = new QName("gov.ornl.stucco", "port-" + UUID.randomUUID().toString(), "stucco");
				
		return new Observable()			//list
				.withId(portId)
				.withTitle("Port")
				.withObservableSources(getMeasureSourceType(source))
				.withObject(new ObjectType()
					.withId(new QName("gov.ornl.stucco", "port-" + port, "stucco"))
					.withDescription(new org.mitre.cybox.common_2.StructuredTextType()
						.withValue(port)) 
					.withProperties(new Port()
						.withPortValue(new PositiveIntegerObjectPropertyType()
							.withValue(port))));
	}

	//TODO remove later
	public Observable getPortObservable(String port, String source)	{

		QName portId = new QName("gov.ornl.stucco", "port-" + UUID.randomUUID().toString(), "stucco");
				
		return new Observable()			//list
				.withId(portId)
				.withTitle("Port")
				.withObservableSources(getMeasureSourceType(source))
				.withObject(new ObjectType()
					.withId(new QName("gov.ornl.stucco", "port-" + port, "stucco"))
					.withDescription(new org.mitre.cybox.common_2.StructuredTextType()
						.withValue(port)) 
					.withProperties(new Port()
						.withPortValue(new PositiveIntegerObjectPropertyType()
							.withValue(port))));
	}

	public Observable setDNSObservable(String dns, String source) {
	
		return new Observable()
			.withId(new QName("gov.ornl.stucco", "dnsName-" + UUID.randomUUID().toString(), "stucco"))	
			.withTitle("DNSName")
			.withObservableSources(getMeasureSourceType("CleanMx(virus)"))
			.withObject(new ObjectType()
				.withId(new QName("gov.ornl.stucco", "dnsName-" + dns, "stucco"))
				.withDescription(new org.mitre.cybox.common_2.StructuredTextType()
					.withValue(dns))
				.withProperties(new WhoisEntry()		
					.withDomainName(getURIObjectType(dns))));
	}

	public Observable setAccountObservable(String user, String source) {
		return new Observable()
			.withId(new QName("gov.ornl.stucco", "account-" + UUID.randomUUID().toString(), "stucco"))	
			.withTitle("Account")
			.withObservableSources(getMeasureSourceType(source))
			.withObject(new ObjectType()
				.withId(new QName("gov.ornl.stucco", "account-" + user, "stucco"))
				.withDescription(new StructuredTextType()
					.withValue(user))
				.withProperties(new UserAccountObjectType()
					.withUsername(new StringObjectPropertyType()
						.withValue(user))
					.withDescription(new StringObjectPropertyType()
						.withValue(user))));
	}
	
	public Observable setSoftwareObservable(String software, String source) {
		return new Observable()
			.withId(new QName("gov.ornl.stucco", "software-" + UUID.randomUUID().toString(), "stucco"))
			.withTitle("Software")
			.withObservableSources(getMeasureSourceType(source))
			.withObject(new ObjectType()
				.withId(new QName("gov.ornl.stucco", "software-" + software, "stucco"))
				.withDescription(new StructuredTextType()
					.withValue(software))
				.withProperties(new Product()
					.withProduct(new StringObjectPropertyType()
						.withValue(software))));
	}
	
	public MalwareInstanceType setMalwareInstance (String id, String source) {
		return new MalwareInstanceType()
			.withId(new QName("gov.ornl.stucco", "malware-" + source + "_" + id, "stucco"))
			.withTypes(new ControlledVocabularyStringType() //list
				.withValue("Malware"))
			.withNames(new ControlledVocabularyStringType() //list
				.withValue(source + "_" + id))
			.withDescriptions(new org.mitre.stix.common_1.StructuredTextType()
				.withValue(source + " entry " + id));
	}

	public RelatedObjectType setRelatedObject(QName idref, String relationship, String description, String source) {
		return new RelatedObjectType() 
			.withIdref(idref)
			.withRelationship(new org.mitre.cybox.common_2.ControlledVocabularyStringType()
				.withValue(relationship))
			.withDescription(new StructuredTextType()
				.withValue(description))
			.withDiscoveryMethod(getMeasureSourceType(source));
	}


	boolean validate(STIXPackage stixPackage) {
		
		try	{
			return stixPackage.validate();
		}			
		catch (SAXException e)	{
			e.printStackTrace();
		}
		return false;
	}
}

