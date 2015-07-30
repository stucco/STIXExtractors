package STIXExtractor;

import javax.xml.namespace.QName;

import java.util.Iterator;
import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.Charset;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.*;

import org.json.*;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Attributes;
import org.jsoup.nodes.Element;
import org.jsoup.parser.Tag;
import org.jsoup.select.Elements;

import org.mitre.stix.stix_1.STIXPackage;
import org.mitre.stix.common_1.ControlledVocabularyStringType;
import org.mitre.cybox.common_2.AnyURIObjectPropertyType;
import org.mitre.cybox.common_2.MeasureSourceType;	
import org.mitre.cybox.common_2. StringObjectPropertyType;
import org.mitre.cybox.common_2.HashType;
import org.mitre.cybox.common_2.SimpleHashValueType;
import org.mitre.cybox.cybox_2.RelatedObjectType;
import org.mitre.cybox.objects.URIObjectType;
import org.mitre.cybox.objects.Address;
import org.mitre.cybox.objects.CategoryTypeEnum;

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

     	public URIObjectType getURIObjectType (String uri)	{
	
     		return new URIObjectType()
        		.withValue(new AnyURIObjectPropertyType()
                		.withValue(uri));
	}

	public MeasureSourceType getMeasureSourceType (String source)	{
	
		return new MeasureSourceType()
                	.withInformationSourceType(new org.mitre.cybox.common_2.ControlledVocabularyStringType()
	                     	.withValue(source));
	}

	public Address getAddress (String address, CategoryTypeEnum category)	{
	
		return new Address()
			.withAddressValue(new StringObjectPropertyType()
				.withValue(address))
			.withCategory(category);
	}

	public HashType getHashType (String hash, String type)	{

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
}

