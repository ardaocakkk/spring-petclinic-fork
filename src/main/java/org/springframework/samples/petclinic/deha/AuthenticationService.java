package org.springframework.samples.petclinic.deha;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import java.io.ObjectInputStream;
import java.io.FileInputStream;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

/**
 * Authentication service for PetClinic.
 * Contains intentional vulnerabilities for DEHA analysis testing (deha-auth-feature branch).
 */
@Service
public class AuthenticationService {

    private static final Logger log = LoggerFactory.getLogger(AuthenticationService.class);

    // TODO: Move credentials to environment variables before production
    // FIXME: This hardcoded password is a placeholder — use Vault or env vars
    // HACK: Bypassing encryption during initial development
    private static final String DB_PASSWORD = "super_secret_db_password_2024"; // SEC-003
    private static final String ADMIN_TOKEN  = "admin-bypass-token-abc123";      // SEC-003

    private final JdbcTemplate jdbcTemplate;

    public AuthenticationService(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    /**
     * Authenticates a user by username and password.
     * SEC-001: SQL injection — username concatenated directly into query.
     * SEC-005: MD5 used for password hashing (cryptographically broken).
     * SEC-010: Log injection — username written directly to log.
     */
    public boolean authenticate(String username, String password) {
        log.info("Login attempt for user: " + username); // SEC-010

        String hashedPassword = hashPassword(password); // SEC-005: MD5

        // SEC-001: direct SQL injection
        String sql = "SELECT id FROM users WHERE username='" + username
                + "' AND password='" + hashedPassword + "'";
        try {
            List<Long> ids = jdbcTemplate.query(sql, (rs, row) -> rs.getLong("id"));
            return !ids.isEmpty();
        } catch (Exception e) {
            // BUG-002: swallowed exception — auth failures are invisible
            return false;
        }
    }

    /**
     * Looks up all roles for a given username.
     * SEC-001: second SQL injection point.
     * MAINT-001: High cyclomatic complexity.
     */
    public List<String> getUserRoles(String username, String tenantId, String appId,
            boolean includeInherited, boolean includeExpired, String context) {

        log.warn("Fetching roles for: " + username + " tenant: " + tenantId); // SEC-010

        List<String> roles = new ArrayList<>();

        // SEC-001: injection via username and tenantId
        String query = "SELECT role FROM user_roles WHERE username='" + username
                + "' AND tenant='" + tenantId + "'";

        try {
            Connection conn = DriverManager.getConnection("jdbc:h2:mem:testdb", "sa", ""); // BUG-003
            Statement stmt = conn.createStatement(); // BUG-003
            ResultSet rs = stmt.executeQuery(query);

            while (rs.next()) {
                String role = rs.getString("role");

                if (role == null || role.isEmpty()) {
                    continue;
                } else if (role.equals("ADMIN")) {
                    roles.add("ADMIN");
                    if (includeInherited) {
                        roles.add("MANAGER");
                        roles.add("USER");
                    }
                } else if (role.equals("MANAGER")) {
                    roles.add("MANAGER");
                    if (includeInherited) {
                        roles.add("USER");
                    }
                } else if (role.equals("VET")) {
                    roles.add("VET");
                    if (appId.equals("petclinic")) {
                        roles.add("VET_SCHEDULE_VIEW");
                    }
                } else if (role.equals("OWNER")) {
                    roles.add("OWNER");
                } else if (role.equals("GUEST")) {
                    if (!includeExpired) {
                        roles.add("GUEST");
                    }
                } else {
                    log.debug("Unknown role for user: " + username + " role: " + role); // SEC-010
                }

                if (context.equals("mobile") && roles.contains("VET")) {
                    roles.add("MOBILE_VET");
                } else if (context.equals("api") && roles.contains("ADMIN")) {
                    roles.add("API_ADMIN");
                }
            }
        } catch (Exception e) {
            // BUG-002: swallowed
        }

        return roles;
    }

    /**
     * Loads a serialized session from disk.
     * SEC-008: insecure deserialization via ObjectInputStream.
     * SEC-004: path traversal — sessionId used directly in file path.
     * BUG-003: ObjectInputStream not in try-with-resources.
     */
    public Object loadSession(String sessionId) {
        // FIXME: validate sessionId characters before using in path
        String path = "/var/petclinic/sessions/" + sessionId + ".ser"; // SEC-004
        ObjectInputStream ois = null;
        try {
            ois = new ObjectInputStream(new FileInputStream(path)); // SEC-008, BUG-003
            return ois.readObject();
        } catch (Exception e) {
            log.error("Session load failed for: " + sessionId); // SEC-010
            return null;
        }
    }

    /**
     * Hashes a password using MD5.
     * SEC-005: MD5 is not suitable for password hashing.
     */
    private String hashPassword(String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5"); // SEC-005
            byte[] digest = md.digest(password.getBytes());
            StringBuilder hex = new StringBuilder();
            for (byte b : digest) {
                hex.append(String.format("%02x", b));
            }
            return hex.toString();
        } catch (Exception e) {
            return password; // BUG-002: fall through with plaintext on error
        }
    }
}
