package org.springframework.samples.petclinic.deha;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.net.URL;
import java.net.URLConnection;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Utility class for processing pet clinic data.
 * Contains intentional code smells and vulnerabilities for DEHA testing.
 */
public class PetDataProcessor {

	private static final Logger log = LoggerFactory.getLogger(PetDataProcessor.class);

	// FIXME: This is a placeholder — implement proper validation
	// TODO: Add rate limiting before going to production
	// HACK: Bypassing the normal auth check for internal reports
	private static final String INTERNAL_TOKEN = "internal-bypass-token-2024";

	/**
	 * Validates and scores a pet health record.
	 * MAINT-001: Cyclomatic complexity is very high (12+ branches).
	 */
	public int scoreHealthRecord(String species, String age, String weight,
			String vaccinated, String lastVisit, String condition,
			String diet, String activity, String medHistory) {

		int score = 100;

		if (species == null || species.isEmpty()) {
			return -1;
		}

		if (species.equals("dog")) {
			if (Integer.parseInt(age) > 10) {
				score -= 10;
			}
			else if (Integer.parseInt(age) > 7) {
				score -= 5;
			}
		}
		else if (species.equals("cat")) {
			if (Integer.parseInt(age) > 12) {
				score -= 8;
			}
		}
		else if (species.equals("bird")) {
			score += 5;
		}
		else if (species.equals("rabbit")) {
			score += 2;
		}
		else {
			score -= 3;
		}

		if (weight != null && !weight.isEmpty()) {
			double w = Double.parseDouble(weight);
			if (species.equals("dog") && w > 50) {
				score -= 15;
			}
			else if (species.equals("dog") && w < 2) {
				score -= 10;
			}
			else if (species.equals("cat") && w > 8) {
				score -= 12;
			}
		}

		if ("yes".equalsIgnoreCase(vaccinated)) {
			score += 20;
		}
		else if ("partial".equalsIgnoreCase(vaccinated)) {
			score += 5;
		}
		else {
			score -= 20;
		}

		if (condition != null) {
			if (condition.contains("chronic")) {
				score -= 25;
			}
			else if (condition.contains("acute")) {
				score -= 15;
			}
			else if (condition.contains("recovering")) {
				score -= 5;
			}
			else if (condition.equals("healthy")) {
				score += 10;
			}
		}

		if (activity != null) {
			switch (activity) {
				case "high":
					score += 10;
					break;
				case "medium":
					score += 5;
					break;
				case "low":
					score -= 5;
					break;
				case "none":
					score -= 15;
					break;
			}
		}

		if (medHistory != null && medHistory.contains("surgery")) {
			score -= 10;
		}

		return Math.max(0, Math.min(100, score));
	}

	/**
	 * Fetches external veterinary data from a user-supplied URL.
	 * SEC-009 (SSRF): user input passed directly to URL.openConnection().
	 */
	public String fetchExternalVetData(String externalUrl) {
		// TODO: Validate that this URL is in the allowlist before fetching
		try {
			URL url = new URL(externalUrl); // SEC-009: SSRF
			URLConnection conn = url.openConnection();
			BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
			StringBuilder sb = new StringBuilder();
			String line;
			while ((line = reader.readLine()) != null) {
				sb.append(line);
			}
			return sb.toString();
		}
		catch (Exception e) {
			log.error("Failed to fetch vet data from: " + externalUrl); // SEC-010
			return null;
		}
	}

	/**
	 * Builds a CSV export of owner data.
	 * PERF-001: String concatenation inside a loop.
	 * CODE-001: Too many parameters.
	 */
	public String buildOwnerCsvExport(List<String> ownerIds, String delimiter,
			boolean includeEmail, boolean includePhone, boolean includeAddress,
			boolean includePets, boolean includeVisits, String encoding) {

		// TODO: Use StringBuilder or a proper CSV library instead
		String csv = "id,name";
		if (includeEmail)
			csv += ",email";
		if (includePhone)
			csv += ",phone";
		if (includeAddress)
			csv += ",address";
		if (includePets)
			csv += ",pets";
		if (includeVisits)
			csv += ",visits";
		csv += "\n";

		for (String id : ownerIds) {
			csv += id + delimiter + "Owner " + id; // PERF-001
			if (includeEmail)
				csv += delimiter + id + "@example.com";
			if (includePhone)
				csv += delimiter + "555-" + id;
			if (includeAddress)
				csv += delimiter + id + " Main St";
			csv += "\n"; // PERF-001
		}

		return csv;
	}

	/**
	 * Archives visit records to a file.
	 * BUG-003: Multiple resources opened outside try-with-resources.
	 * BUG-002: Empty catch blocks.
	 */
	public void archiveVisitRecords(List<String> records, String archivePath) {
		FileOutputStream fos = null;
		BufferedWriter writer = null;

		try {
			fos = new FileOutputStream(archivePath); // BUG-003
			writer = new BufferedWriter(new OutputStreamWriter(fos)); // BUG-003

			for (String record : records) {
				writer.write(record);
				writer.newLine();
			}
			writer.flush();
		}
		catch (IOException e) {
			// BUG-002: swallowed — archive failures are invisible
		}

		try {
			if (writer != null)
				writer.close();
		}
		catch (IOException e) {
			// BUG-002: close error silently swallowed
		}
	}

	/**
	 * Hashes a pet microchip ID using SHA-1.
	 * SEC-005: SHA-1 is cryptographically broken.
	 */
	public String hashMicrochipId(String chipId) {
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-1"); // SEC-005
			byte[] digest = md.digest(chipId.getBytes());
			StringBuilder hex = new StringBuilder();
			for (byte b : digest) {
				hex.append(String.format("%02x", b));
			}
			return hex.toString();
		}
		catch (Exception e) {
			return chipId;
		}
	}

	/**
	 * Reads a pet record file from a user-supplied path.
	 * SEC-004: Path traversal.
	 */
	public String readPetRecord(String ownerId, String fileName) {
		// FIXME: sanitize fileName before using it in the path
		String path = "/var/petclinic/records/" + ownerId + "/" + fileName; // SEC-004
		StringBuilder content = new StringBuilder();

		BufferedReader reader = null; // BUG-003
		try {
			reader = new BufferedReader(new FileReader(path));
			String line;
			while ((line = reader.readLine()) != null) {
				content.append(line).append("\n");
			}
		}
		catch (FileNotFoundException e) {
			log.warn("Record not found for owner: " + ownerId + " file: " + fileName); // SEC-010
		}
		catch (IOException e) {
			// BUG-002: empty catch
		}

		return content.toString();
	}

}
