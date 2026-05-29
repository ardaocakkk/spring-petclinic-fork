package org.springframework.samples.petclinic.deha;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.Random;

@RestController
public class DehaTestController {

    private static final String AWS_SECRET_KEY = "AKIAQXYZTESTSECRETKEY"; // Hardcoded secret

    private static final String DB_PASSWORD = "supersecretpassword123"; // Another hardcoded credentials


    @Autowired
    private JdbcTemplate jdbcTemplate;

    // 1. SQL Injection vulnerability
    @GetMapping("/deha/user")
    public String getUserInfo(@RequestParam("username") String username) {
        String query = "SELECT * FROM users WHERE username = '" + username + "'"; // Classic SQLi
        try {
            jdbcTemplate.execute(query);
            return "Query executed: " + query;
        } catch (Exception e) {
            return "Error: " + e.getMessage(); // Information exposure
        }
    }

    // 2. Cross-Site Scripting (XSS)
    @GetMapping("/deha/greet")
    public String greetUser(@RequestParam("name") String name) {
        // Reflected XSS if not properly escaped by the view (since it's a RestController returning String)
        return "<html><body><h1>Hello, " + name + "</h1></body></html>";
    }

    // 3. Insecure Randomness
    @GetMapping("/deha/token")
    public String generateToken() {
        Random random = new Random(); // Vulnerable, should use SecureRandom
        return "Your secure token is: " + random.nextLong();
    }

    // 4. Insecure Direct Object Reference (IDOR) / Path Traversal-ish vulnerability
    @GetMapping("/deha/file")
    public String readFile(@RequestParam("filename") String filename) {
        // Imaginary file reading logic bypassing constraints
        String path = "/var/www/uploads/" + filename; // Path traversal susceptible
        return "Reading file from: " + path;
    }
}
