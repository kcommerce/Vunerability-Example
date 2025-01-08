import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

public class VulnerableExample {

    // A01:2021-Broken Access Control
    public void brokenAccessControl(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        String userRole = (String) session.getAttribute("role");
        if (userRole.equals("admin")) {
            // Sensitive operation without proper access control checks
            response.getWriter().write("Access granted to admin section");
        }
    }

    // A02:2021-Cryptographic Failures
    public String insecureHash(String input) throws Exception {
        // Using MD5 for hashing, which is considered insecure
        java.security.MessageDigest md = java.security.MessageDigest.getInstance("MD5");
        byte[] hash = md.digest(input.getBytes());
        return new String(hash);
    }

    // A03:2021-Injection
    public void sqlInjection(HttpServletRequest request) throws Exception {
        String userId = request.getParameter("userId");
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE userId = '" + userId + "'");
        while (rs.next()) {
            System.out.println("User: " + rs.getString("username"));
        }
    }

    // A04:2021-Insecure Design
    public void insecureDesign(HttpServletRequest request) {
        String userInput = request.getParameter("userInput");
        // Potential XSS vulnerability
        System.out.println("User Input: " + userInput);
    }

    // A05:2021-Security Misconfiguration
    public void securityMisconfiguration() {
        // Disabling SSL certificate validation
        javax.net.ssl.HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> true);
    }

    // A06:2021-Vulnerable and Outdated Components
    public void vulnerableComponent() {
        // Using a vulnerable version of a library
        org.apache.commons.codec.digest.DigestUtils.md5Hex("vulnerable");
    }

    // A07:2021-Identification and Authentication Failures
    public void authFailures(HttpServletRequest request, HttpServletResponse response) throws Exception {
        // Using hardcoded credentials
        String username = "admin";
        String password = "password123";
        if (request.getParameter("username").equals(username) && request.getParameter("password").equals(password)) {
            response.getWriter().write("Authentication successful");
        }
    }

    // A08:2021-Software and Data Integrity Failures
    public void integrityFailures() throws Exception {
        // Loading a class dynamically from user input
        String className = "example." + System.getProperty("userClassName");
        Class<?> clazz = Class.forName(className);
        Object instance = clazz.getDeclaredConstructor().newInstance();
    }

    // A09:2021-Security Logging and Monitoring Failures
    public void loggingFailures(HttpServletRequest request) {
        // Logging sensitive information
        String username = request.getParameter("username");
        System.out.println("User login attempt: " + username);
    }

    // A10:2021-Server-Side Request Forgery (SSRF)
    public void ssrf(HttpServletRequest request) throws Exception {
        // Fetching a URL based on user input
        String url = request.getParameter("url");
        java.net.URLConnection connection = new java.net.URL(url).openConnection();
        connection.connect();
    }
}
