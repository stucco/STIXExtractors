package STIXExtractor;

import java.util.List;
import java.util.UUID;

import java.io.IOException;

import javax.xml.namespace.QName;
import javax.xml.datatype.DatatypeConfigurationException;

import org.apache.commons.csv.CSVRecord;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.mitre.stix.stix_1.STIXPackage;
import org.mitre.cybox.cybox_2.Observables;
import org.mitre.cybox.cybox_2.Observable;
import org.mitre.cybox.common_2.CustomPropertiesType;
import org.mitre.cybox.common_2.StringObjectPropertyType;
import org.mitre.cybox.cybox_2.ObjectType;
import org.mitre.cybox.objects.Port;
import org.mitre.cybox.objects.PortListType;
import org.mitre.cybox.objects.ProcessObjectType;

/**
 * ServiceList to STIX format extractor.
 *
 * @author Maria Vincent
 */
public class ServiceListExtractor extends STIXExtractor {
						
	private static final Logger logger = LoggerFactory.getLogger(ServiceListExtractor.class);
	private static String[] HEADERS = {"Service Name","Port Number","Transport Protocol","Description","Assignee","Contact","Registration Date",
					   "Modification Date","Reference","Service Code","Known Unauthorized Uses","Assignment Notes"};
	private static final String SERVICE_NAME = "Service Name";
	private static final String PORT_NUMBER = "Port Number";
	private static final String DESCRIPTION = "Description";
	private static final String REFERENCE = "Reference";
	private static final String ASSIGNMENT_NOTES = "Assignment Notes";

	private STIXPackage stixPackage;
	private Observables observables;
	
	public ServiceListExtractor(String serviceListInfo) {
		stixPackage = extract(serviceListInfo);
	}
					
	public STIXPackage getStixPackage() {
		return stixPackage;
	}

	private STIXPackage extract (String serviceListInfo) {
		try {
			List<CSVRecord> records = getCSVRecordsList(HEADERS, serviceListInfo);
			
			if (records.isEmpty()) {
				return null;
			}

			CSVRecord record = records.get(0);
			int start;
			if (record.get(0).equals(SERVICE_NAME))	{
				if (records.size() == 1)	{
					return null;
				} else {
					start = 1;
				}
			} else {
				start = 0;
			}
						
			stixPackage = initStixPackage("Service Description", "service_list");				
			observables = initObservables();

			for (int i = start; i < records.size(); i++) {

				record = records.get(i);
				
				if (record.get(PORT_NUMBER).isEmpty() || record.get(SERVICE_NAME).isEmpty()) {
					continue;
				}

				/* Port */
				Observable portObservable = setPortObservable(record.get(PORT_NUMBER), "service_list");

				CustomPropertiesType properties = new CustomPropertiesType()
						.withProperties(setCustomProperty("Notes", record.get(ASSIGNMENT_NOTES)))
						.withProperties(setCustomProperty("Reference", record.get(REFERENCE)));
		
				System.out.println(record.get(SERVICE_NAME) + " " + properties.getProperties().isEmpty());
				/* Process(Service) */
				Observable processObservable = new Observable()
					.withId(new QName("gov.ornl.stucco", "service-" + UUID.randomUUID().toString(), "stucco"))	
					.withTitle("Service")
					.withObservableSources(setMeasureSourceType("service_list"))
					.withObject(new ObjectType()
						.withId(new QName("gov.ornl.stucco", "service-" + makeId(record.get(SERVICE_NAME)), "stucco"))
						.withDescription((record.get(DESCRIPTION).isEmpty()) ? null : new org.mitre.cybox.common_2.StructuredTextType()
							.withValue(record.get(DESCRIPTION))) 
						.withProperties(new ProcessObjectType()
							.withName(new StringObjectPropertyType()
								.withValue(record.get(SERVICE_NAME)))
							.withCustomProperties((properties.getProperties().isEmpty()) ? null : properties)
							.withPortList(new PortListType()
								.withPorts(new Port()
									.withObjectReference(portObservable.getId())))));
				observables
					.withObservables(portObservable)
					.withObservables(processObservable);
			}

			return (observables.getObservables().isEmpty()) ? null : initStixPackage("server_banner").withObservables(observables);	

		} catch (DatatypeConfigurationException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}

		return null;
	}
}
