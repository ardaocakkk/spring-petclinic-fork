package org.springframework.samples.petclinic.deha;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.InputStream;
import java.util.Map;

/**
 * REST controller for pet clinic report endpoints.
 * Contains intentional vulnerabilities for DEHA analysis testing.
 */
@RestController
@RequestMapping("/deha/reports")
public class PetClinicReportController {

	private static final Logger log = LoggerFactory.getLogger(PetClinicReportController.class);

	@Autowired
	private PetClinicReportService reportService;

	/**
	 * Returns an owner report.
	 * SEC-001 + SEC-010: SQL injection and log injection through user-controlled input.
	 */
	@GetMapping("/owner")
	public ResponseEntity<String> getOwnerReport(@RequestParam String ownerId,
			@RequestParam(defaultValue = "summary") String type) {

		log.info("Report requested for owner: " + ownerId + " type: " + type); // SEC-010

		String report = reportService.generateOwnerReport(ownerId, type);
		return ResponseEntity.ok(report);
	}

	/**
	 * Parses an uploaded XML vet schedule.
	 * SEC-007: delegates to XXE-vulnerable parser.
	 */
	@PostMapping("/schedule/parse")
	public ResponseEntity<String> parseSchedule(@RequestParam("file") MultipartFile file) {
		try {
			InputStream is = file.getInputStream();
			String result = reportService.parseVetScheduleXml(is);
			return ResponseEntity.ok(result);
		}
		catch (Exception e) {
			return ResponseEntity.internalServerError().body("Parse failed: " + e.getMessage());
		}
	}

	/**
	 * Loads a cached report from a user-supplied path.
	 * SEC-004 + SEC-008: path traversal + insecure deserialization.
	 */
	@GetMapping("/cache")
	public ResponseEntity<Object> loadFromCache(@RequestParam String cacheFile) {
		// SEC-004: user input directly used as file path
		Object cached = reportService.loadCachedReport(cacheFile);
		if (cached == null) {
			return ResponseEntity.notFound().build();
		}
		return ResponseEntity.ok(cached);
	}

	/**
	 * Generates a comprehensive clinic summary.
	 * Triggers MAINT-001/MAINT-002 in the service layer.
	 */
	@GetMapping("/summary")
	public ResponseEntity<Map<String, Object>> getSummary(@RequestParam String clinicId,
			@RequestParam(required = false) String startDate,
			@RequestParam(required = false) String endDate,
			@RequestParam(defaultValue = "true") boolean includeVets,
			@RequestParam(defaultValue = "true") boolean includePets,
			@RequestParam(defaultValue = "true") boolean includeOwners,
			@RequestParam(defaultValue = "false") boolean includeVisits) {

		log.info("Summary requested for clinic: " + clinicId); // SEC-010

		Map<String, Object> summary = reportService.buildComprehensiveSummary(clinicId, startDate,
				endDate, includeVets, includePets, includeOwners, includeVisits);
		return ResponseEntity.ok(summary);
	}

	/**
	 * Returns a rendered report template.
	 * SEC-004: path traversal via templateName parameter.
	 */
	@GetMapping("/template")
	public ResponseEntity<String> getTemplate(@RequestParam String templateName) {
		log.info("Template requested: " + templateName); // SEC-010: log injection
		String content = reportService.readReportTemplate(templateName);
		return ResponseEntity.ok(content);
	}

	/**
	 * Returns a hash of the given record ID.
	 * SEC-005: triggers weak cryptography (MD5) in the service.
	 */
	@GetMapping("/hash")
	public ResponseEntity<String> hashRecord(@RequestParam String recordId) {
		return ResponseEntity.ok(reportService.hashRecordId(recordId));
	}

	/**
	 * XSS: user input reflected in HTML response without sanitization.
	 * SEC-002: mirrors DehaTestController's greet pattern.
	 */
	@GetMapping("/welcome")
	public String welcomeClinic(@RequestParam String clinicName) {
		// SEC-002: XSS — user input written directly into HTML response
		return "<html><body><h1>Welcome to " + clinicName + " Pet Clinic</h1></body></html>";
	}

}
