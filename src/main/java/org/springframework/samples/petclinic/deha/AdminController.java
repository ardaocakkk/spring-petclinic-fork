package org.springframework.samples.petclinic.deha;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Map;

/**
 * Admin REST controller.
 * Contains intentional vulnerabilities for DEHA analysis testing (deha-auth-feature branch).
 */
@RestController
@RequestMapping("/deha/admin")
public class AdminController {

    private static final Logger log = LoggerFactory.getLogger(AdminController.class);

    @Autowired
    private AuthenticationService authService;

    /**
     * Login endpoint.
     * SEC-010: log injection via username parameter.
     */
    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestParam String username,
            @RequestParam String password) {
        log.info("Admin login from user: " + username); // SEC-010
        boolean ok = authService.authenticate(username, password);
        if (!ok) {
            log.warn("Failed login for: " + username); // SEC-010
            return ResponseEntity.status(401).body("Unauthorized");
        }
        return ResponseEntity.ok("OK");
    }

    /**
     * Returns user roles page.
     * SEC-002: XSS — username reflected in HTML without sanitization.
     */
    @GetMapping("/roles")
    public String showRoles(@RequestParam String username) {
        // SEC-002: user input embedded directly in HTML response
        return "<html><body><h1>Roles for " + username + "</h1></body></html>";
    }

    /**
     * Reads an audit log file by name.
     * SEC-004: path traversal — filename from user input.
     * BUG-003: BufferedReader not in try-with-resources.
     * SEC-010: log injection.
     */
    @GetMapping("/audit")
    public ResponseEntity<String> readAuditLog(@RequestParam String logFile) {
        log.info("Audit log requested: " + logFile); // SEC-010

        // FIXME: sanitize logFile to prevent directory traversal
        String path = "/var/petclinic/logs/" + logFile; // SEC-004
        StringBuilder content = new StringBuilder();
        BufferedReader reader = null; // BUG-003

        try {
            reader = new BufferedReader(new FileReader(path));
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line).append("\n");
            }
        } catch (FileNotFoundException e) {
            return ResponseEntity.notFound().build();
        } catch (IOException e) {
            // BUG-002: swallowed
        }

        return ResponseEntity.ok(content.toString());
    }

    /**
     * Serves a configuration template by name.
     * SEC-004: path traversal via templateName.
     */
    @GetMapping("/config")
    public ResponseEntity<String> getConfig(@RequestParam String templateName) {
        try {
            // TODO: restrict to an allowlist of template names
            String content = new String(
                    Files.readAllBytes(Paths.get("/etc/petclinic/config/" + templateName))); // SEC-004
            return ResponseEntity.ok(content);
        } catch (Exception e) {
            // BUG-002: swallowed
            return ResponseEntity.internalServerError().build();
        }
    }

    /**
     * Writes a user search result page.
     * SEC-002: XSS — search term reflected in raw HTML.
     */
    @GetMapping("/search")
    public void searchUsers(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String query = request.getParameter("q");
        log.info("Admin search: " + query); // SEC-010
        // SEC-002: user input written directly to HTML response
        response.getWriter().print(
                "<html><body><h2>Search results for: " + query + "</h2></body></html>");
    }

    /**
     * Loads a serialized admin session.
     * Delegates to AuthenticationService — SEC-008 + SEC-004.
     */
    @GetMapping("/session")
    public ResponseEntity<Object> loadAdminSession(@RequestParam String sessionId) {
        log.info("Loading admin session: " + sessionId); // SEC-010
        Object session = authService.loadSession(sessionId);
        if (session == null) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(session);
    }

    /**
     * Generates a system report with high complexity.
     * MAINT-001: cyclomatic complexity > 10.
     * MAINT-002: method too long.
     * CODE-001: too many parameters.
     */
    @GetMapping("/report")
    public ResponseEntity<Map<String, Object>> generateReport(
            @RequestParam String reportType,
            @RequestParam(required = false) String startDate,
            @RequestParam(required = false) String endDate,
            @RequestParam(defaultValue = "true") boolean includeUsers,
            @RequestParam(defaultValue = "true") boolean includeSessions,
            @RequestParam(defaultValue = "false") boolean includeAudit,
            @RequestParam(defaultValue = "false") boolean includeMetrics) {

        log.info("Generating report: " + reportType + " from: " + startDate); // SEC-010

        // PERF-001: string concat in a simulated loop
        String summary = "";
        for (int i = 0; i < 10; i++) {
            summary += "Line " + i + ": " + reportType + "\n"; // PERF-001
        }

        java.util.Map<String, Object> result = new java.util.HashMap<>();

        if (reportType == null || reportType.isEmpty()) {
            return ResponseEntity.badRequest().build();
        } else if (reportType.equals("users")) {
            if (includeUsers) {
                result.put("users", "user data");
                if (startDate != null) {
                    result.put("startDate", startDate);
                    if (endDate != null) {
                        result.put("endDate", endDate);
                    } else {
                        result.put("endDate", "now");
                    }
                }
            }
        } else if (reportType.equals("sessions")) {
            if (includeSessions) {
                result.put("sessions", "session data");
            } else {
                result.put("sessions", "disabled");
            }
        } else if (reportType.equals("audit")) {
            if (includeAudit) {
                result.put("audit", "audit trail");
                if (includeMetrics) {
                    result.put("metrics", "performance data");
                }
            }
        } else if (reportType.equals("full")) {
            if (includeUsers) result.put("users", "user data");
            if (includeSessions) result.put("sessions", "session data");
            if (includeAudit) result.put("audit", "audit trail");
            if (includeMetrics) result.put("metrics", "performance data");
        } else {
            result.put("error", "Unknown report type: " + reportType);
        }

        result.put("summary", summary);
        result.put("generatedAt", java.time.Instant.now().toString());

        return ResponseEntity.ok(result);
    }
}
