package STIXExtractor;

import java.util.GregorianCalendar;
import java.util.UUID;
import java.util.Set;
import java.util.Map;
import java.util.HashMap;
import java.util.Iterator;

import java.math.BigInteger;

import org.json.JSONObject;
import org.json.JSONArray;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.xml.namespace.QName;				
import javax.xml.datatype.DatatypeConfigurationException;

import org.mitre.stix.stix_1.STIXPackage;
import org.mitre.stix.common_1.ExploitTargetsType;
import org.mitre.stix.common_1.StructuredTextType;
import org.mitre.stix.common_1.DateTimeWithPrecisionType;
import org.mitre.stix.common_1.ReferencesType;
import org.mitre.stix.common_1.RelatedObservableType;
import org.mitre.stix.exploittarget_1.VulnerabilityType;
import org.mitre.stix.exploittarget_1.CVSSVectorType;
import org.mitre.stix.exploittarget_1.AffectedSoftwareType;
import org.mitre.stix.exploittarget_1.ExploitTarget;
import org.mitre.cybox.cybox_2.Observables;
import org.mitre.cybox.cybox_2.Observable;
import org.mitre.cybox.cybox_2.ObjectType;
import org.mitre.cybox.cybox_2.RelatedObjectsType;
import org.mitre.cybox.cybox_2.RelatedObjectType;
import org.mitre.cybox.common_2.StringObjectPropertyType;
import org.mitre.cybox.objects.FileObjectType;
import org.mitre.cybox.objects.Product;
import org.mitre.cybox.objects.API;

/** 
 * Stucco extracted data from unstructured sources to STIX 
 *
 * @author Maria Vincent
 */
public class StuccoExtractor extends STIXExtractor {
							
	private static final Logger logger = LoggerFactory.getLogger(StuccoExtractor.class);
	
	private STIXPackage stixPackage;
	private Observables observables;
	private ExploitTargetsType ets;
	private GregorianCalendar calendar;

	public StuccoExtractor(JSONObject stuccoInfo) {
		stixPackage = (stuccoInfo == null) ? null : extract(stuccoInfo);
	}
					
	public STIXPackage getStixPackage() {
		return stixPackage;
	}

	private STIXPackage extract(JSONObject stuccoInfo) {
		JSONObject vertices = stuccoInfo.optJSONObject("vertices");
		if (vertices == null) {
			return null;
		}
		JSONArray edges = stuccoInfo.optJSONArray("edges");
		observables = initObservables();
		ets = new ExploitTargetsType();
		calendar = new GregorianCalendar();
		Map<String, Object> stuccoMap = new HashMap<String, Object>();
		Set<Object> keys = vertices.keySet();
		Iterator<Object> iterator = keys.iterator();
		//constructing vertices
		while (iterator.hasNext()) {
			String key = iterator.next().toString();
			JSONObject vertex = vertices.getJSONObject(key);
			String type = vertex.getString("vertexType");
			switch (type) {
				case "vulnerability":
					ExploitTarget et = constructVulnerability(vertex);
					ets
						.withExploitTargets(et);
					stuccoMap.put(key, et);
					break;
				case "software":
					Observable software = constructSoftware(vertex);
					observables
						.withObservables(software);
					stuccoMap.put(key, software);
					break;
				case "file":
					Observable file = constructFile(vertex);
					observables
						.withObservables(file);
					stuccoMap.put(key, file);
					break;
				case "function":
					Observable function = constructFunction(vertex); 
					observables
						.withObservables(function);
					stuccoMap.put(key, function);
					break;
			}
			iterator.remove();
		}

		if (edges != null) {
			//constructing edges
			for (int i = 0; i < edges.length(); i++) {
				JSONObject edge = edges.getJSONObject(i);
				String outVertID = edge.getString("outVertID");
				String inVertID = edge.getString("inVertID");
				String relation = edge.getString("relation");
				switch (relation) {
					case "ExploitTargetRelatedObservable" :
						ExploitTarget et = (ExploitTarget) stuccoMap.get(outVertID);
						Observable observable = (Observable) stuccoMap.get(inVertID);
						constructExploitTargetRelatedObservable(et, observable);
						break;
					case "Sub-Observable":
						Observable outOobservable = (Observable) stuccoMap.get(outVertID);
						Observable inObservable = (Observable) stuccoMap.get(inVertID);
						constructSubObservable(outOobservable, inObservable);
						break;
					default:
						logger.debug("Unknow relation: " + relation + "; came from document: " + stuccoInfo);
						break;
				}
			}
		}

		if (!observables.getObservables().isEmpty()) {
			try {
				stixPackage = initStixPackage("NVD")
					.withObservables(observables);
			} catch(DatatypeConfigurationException e) {
				e.printStackTrace();
			}
		}
		
		if (!ets.getExploitTargets().isEmpty()) {
			if (stixPackage == null) {
				try {
					stixPackage = initStixPackage("NVD")
						.withExploitTargets(ets);
				} catch(DatatypeConfigurationException e) {
					e.printStackTrace();
				}
			} else {
				stixPackage
					.withExploitTargets(ets);
			}
		}

		return stixPackage;
	}

	private ExploitTarget constructVulnerability(JSONObject vertex) {
		VulnerabilityType vulnerability = new VulnerabilityType();
		//cve
		if (vertex.has("cve")) {
			vulnerability
					.withCVEID(vertex.getString("cve"));
		} 
		
		//description
		if (vertex.has("description")) {
			vulnerability
				.withDescriptions(new StructuredTextType()             
					.withValue(vertex.getString("description")));
		}

		//name = svdbid
		if (vertex.has("name")) {
			vulnerability
				.withOSVDBID(new BigInteger(vertex.getString("name")));
		}

		//source 
		if (vertex.has("source")) {
			vulnerability
 				.withSource(vertex.getString("source"));
		}

		//ms = short description
		//TODO: think about differet place for this id, since there is no ms_id field 
		if (vertex.has("ms")) {
			vulnerability
				.withShortDescriptions(new StructuredTextType()             
					.withValue(vertex.getString("ms")));
		}

		QName id = new QName("gov.ornl.stucco", "vulnerability-" + UUID.randomUUID().toString(), "stucco");
		ExploitTarget et = new ExploitTarget()
				.withId(id)
				.withTitle("Vulnerability")
				.withVulnerabilities(vulnerability);

		return et;
	}

	private Observable constructSoftware(JSONObject vertex) {
		Observable software = new Observable();
		Product product = new Product();

		//product
		if (vertex.has("product")) {
			product
				.withProduct(new StringObjectPropertyType()
					.withValue(vertex.getString("product")));
		}

		//vendor
		if (vertex.has("vendor")) {
			product
				.withVendor(new StringObjectPropertyType()
					.withValue(vertex.getString("vendor")));
		}

		//source
		if (vertex.has("source")) {
			software
				.withObservableSources(setMeasureSourceType(vertex.getString("source")));
		}

		QName id = new QName("gov.ornl.stucco", "software-" + UUID.randomUUID().toString(), "stucco");
		software
			.withId(id)
			.withTitle("Software")
			.withObject(new ObjectType()
				.withProperties(product));

		return software;
	}

	private Observable constructFile(JSONObject vertex) {
		Observable file = new Observable();
		FileObjectType fileObject = new FileObjectType();

		//file name
		if (vertex.has("name")) {
			fileObject
				.withFileName(new StringObjectPropertyType()
					.withValue(vertex.getString("name")));
		}

		//source
		if (vertex.has("source")) {
			file
				.withObservableSources(setMeasureSourceType(vertex.getString("source")));
		}

		QName id = new QName("gov.ornl.stucco", "file-" + UUID.randomUUID().toString(), "stucco");
		file
			.withId(id)
			.withTitle("File")
			.withObject(new ObjectType()
				.withProperties(fileObject));

		return file;
	}

	private Observable constructFunction(JSONObject vertex) {
		Observable function = new Observable();
		API api = new API();

		//function name
		if (vertex.has("name")) {
			api
				.withFunctionName(new StringObjectPropertyType()
					.withValue(vertex.getString("name")));
		}

		//source
		if (vertex.has("source")) {
			function
				.withObservableSources(setMeasureSourceType(vertex.getString("source")));
		}

		QName id = new QName("gov.ornl.stucco", "function-" + UUID.randomUUID().toString(), "stucco");
		function
			.withId(id)
				.withTitle("Function")
				.withObject(new ObjectType()
					.withProperties(api));

		return function;
	}

	private void constructExploitTargetRelatedObservable(ExploitTarget et, Observable observable) {
		VulnerabilityType vulnerability = et.getVulnerabilities().get(0);
		AffectedSoftwareType affectedSoftware = null;
		if (vulnerability.getAffectedSoftware() == null) {
			affectedSoftware = new AffectedSoftwareType();
			vulnerability
				.withAffectedSoftware(affectedSoftware);
		} else {
			affectedSoftware = vulnerability.getAffectedSoftware();
		}

		affectedSoftware
			.withAffectedSoftwares(new RelatedObservableType()
				.withObservable(new Observable()
					.withIdref(observable.getId())));

	}

	private void constructSubObservable(Observable outObservable, Observable inObservable) {
		ObjectType object = outObservable.getObject();
		RelatedObjectsType relatedObjects = object.getRelatedObjects();
		if (relatedObjects == null) {
			relatedObjects = new RelatedObjectsType();
			object
				.withRelatedObjects(relatedObjects);
		}
		relatedObjects
			.withRelatedObjects(new RelatedObjectType()
				.withIdref(inObservable.getId()));
	}
}
