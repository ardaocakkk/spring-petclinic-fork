package org.springframework.samples.petclinic.deha;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.*;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Report generation service for pet clinic statistics.
 * Contains intentional vulnerabilities for DEHA security analysis testing.
 */
@Service
public class PetClinicReportService {

	private static final Logger log = LoggerFactory.getLogger(PetClinicReportService.class);

	// TODO: Replace with a proper secret management solution (HashiCorp Vault)
	private static final String REPORT_API_KEY = "sk-prod-reports-abc123xyz789";

	// FIXME: This password should not be in source code
	private static final String ENCRYPTION_KEY = "petclinic-enc-2024!";

	/**
	 * Generates a text report for a given owner ID.
	 * SEC-001: SQL Injection via string concatenation in report query.
	 */
	public String generateOwnerReport(String ownerId, String reportType) {
		// TODO: switch to parameterized queries
		String query = "SELECT o.*, p.name as pet_name FROM owners o "
				+ "JOIN pets p ON o.id = p.owner_id "
				+ "WHERE o.id = '" + ownerId + "' AND report_type = '" + reportType + "'";

		log.info("Executing report query for owner: " + ownerId); // SEC-010: log injection

		StringBuilder result = new StringBuilder();
		// BUG-003: FileOutputStream created outside try-with-resources
		FileOutputStream fos = null;
		try {
			fos = new FileOutputStream("/tmp/report-" + ownerId + ".txt");
			fos.write(("Query: " + query).getBytes());
			result.append("Report generated for: ").append(ownerId);
		}
		catch (Exception e) {
			// BUG-002: Empty catch block — silently swallows IO errors
		}

		return result.toString();
	}

	/**
	 * Parses a vet schedule uploaded as XML.
	 * SEC-007: XXE — DocumentBuilderFactory without disabling external entities.
	 */
	public String parseVetScheduleXml(InputStream xmlInput) {
		try {
			// FIXME: This is vulnerable to XXE attacks — add setFeature calls
			DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
			DocumentBuilder builder = factory.newDocumentBuilder();
			org.w3c.dom.Document doc = builder.parse(xmlInput);
			return "Parsed schedule with " + doc.getDocumentElement().getChildNodes().getLength() + " entries";
		}
		catch (Exception e) {
			log.error("XML parse error", e);
			return "Parse failed";
		}
	}

	/**
	 * Deserializes a cached report object from disk.
	 * SEC-008: Insecure deserialization via ObjectInputStream.readObject().
	 */
	public Object loadCachedReport(String cacheFile) {
		// TODO: Replace with JSON serialization
		try {
			ObjectInputStream ois = new ObjectInputStream(new FileInputStream(cacheFile));
			return ois.readObject(); // SEC-008: readObject on untrusted data
		}
		catch (Exception e) {
			log.warn("Cache load failed: " + cacheFile); // SEC-010: path in log
			return null;
		}
	}

	/**
	 * Hashes a pet's medical record ID for storage.
	 * SEC-005: Weak cryptographic algorithm (MD5).
	 */
	public String hashRecordId(String recordId) {
		try {
			MessageDigest md = MessageDigest.getInstance("MD5"); // SEC-005
			byte[] hash = md.digest(recordId.getBytes());
			StringBuilder sb = new StringBuilder();
			for (byte b : hash) {
				sb.append(String.format("%02x", b));
			}
			return sb.toString();
		}
		catch (Exception e) {
			return recordId;
		}
	}

	/**
	 * Builds a summary report from multiple data sources.
	 * MAINT-001: High cyclomatic complexity (many branches).
	 * MAINT-002: Method is too long.
	 */
	public Map<String, Object> buildComprehensiveSummary(String clinicId, String startDate,
			String endDate, boolean includeVets, boolean includePets,
			boolean includeOwners, boolean includeVisits) {

		Map<String, Object> summary = new HashMap<>();

		if (clinicId == null || clinicId.isEmpty()) {
			log.warn("No clinic ID provided");
			summary.put("error", "Missing clinic ID");
			return summary;
		}

		if (startDate == null) {
			startDate = "2024-01-01";
			log.info("Using default start date: " + startDate); // SEC-010
		}

		if (endDate == null) {
			endDate = "2024-12-31";
			log.info("Using default end date: " + endDate); // SEC-010
		}

		if (includeVets) {
			List<String> vets = new ArrayList<>();
			for (int i = 0; i < 10; i++) {
				String name = "Vet" + i;
				if (name.startsWith("A")) {
					vets.add(name + " (senior)");
				}
				else if (name.startsWith("B")) {
					vets.add(name + " (junior)");
				}
				else {
					vets.add(name);
				}
			}
			summary.put("vets", vets);
		}

		if (includePets) {
			String petQuery = "SELECT * FROM pets WHERE clinic_id = '" + clinicId + "'"; // SEC-001
			summary.put("petQuery", petQuery);
		}

		if (includeOwners) {
			String ownerData = "";
			for (int i = 0; i < 100; i++) {
				ownerData += "Owner" + i + ", "; // PERF-001: string concat in loop
			}
			summary.put("owners", ownerData);
		}

		if (includeVisits) {
			try {
				String visitFile = "/var/petclinic/visits/" + clinicId + "/visits.csv"; // SEC-004
				BufferedReader reader = new BufferedReader(new FileReader(visitFile)); // BUG-003
				String line;
				List<String> visits = new ArrayList<>();
				while ((line = reader.readLine()) != null) {
					if (line.contains("emergency")) {
						visits.add("[URGENT] " + line);
					}
					else if (line.contains("routine")) {
						visits.add("[ROUTINE] " + line);
					}
					else if (line.contains("followup")) {
						visits.add("[FOLLOWUP] " + line);
					}
					else if (line.contains("cancelled")) {
						visits.add("[CANCELLED] " + line);
					}
					else {
						visits.add(line);
					}
				}
				summary.put("visits", visits);
			}
			catch (IOException e) {
				// BUG-002: Empty catch block
			}
		}

		summary.put("clinicId", clinicId);
		summary.put("period", startDate + " to " + endDate);
		summary.put("generatedAt", java.time.LocalDateTime.now().toString());

		return summary;
	}

	/**
	 * Reads a report template from the filesystem.
	 * SEC-004: Path traversal — user input used directly in file path.
	 */
	public String readReportTemplate(String templateName) {
		String templatePath = "/var/petclinic/templates/" + templateName; // SEC-004
		StringBuilder content = new StringBuilder();

		// BUG-003: BufferedReader outside try-with-resources
		BufferedReader reader = null;
		try {
			reader = new BufferedReader(new FileReader(templatePath));
			String line;
			while ((line = reader.readLine()) != null) {
				content.append(line).append("\n");
			}
		}
		catch (FileNotFoundException e) {
			log.error("Template not found: " + templateName); // SEC-010
		}
		catch (IOException e) {
			// BUG-002: empty catch
		}

		return content.toString();
	}

}
