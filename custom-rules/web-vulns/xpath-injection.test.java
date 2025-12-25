// Test cases for java-xpath-injection rule

import javax.xml.xpath.*;
import org.springframework.web.bind.annotation.*;

public class XPathTest {

    // =========================================================================
    // TRUE POSITIVES - Should be detected
    // =========================================================================

    // ruleid: java-xpath-injection
    @GetMapping("/user")
    public User findUser(@RequestParam("username") String username) {
        XPath xpath = XPathFactory.newInstance().newXPath();
        String expression = "//user[name='" + username + "']";
        Node result = (Node) xpath.evaluate(expression, doc, XPathConstants.NODE);
        return parseUser(result);
    }

    // ruleid: java-xpath-injection
    @PostMapping("/login")
    public String login(@RequestParam("user") String user, @RequestParam("pass") String pass) {
        XPath xpath = XPathFactory.newInstance().newXPath();
        String query = "//user[username='" + user + "' and password='" + pass + "']";
        XPathExpression expr = xpath.compile(query);
        return expr.evaluate(doc);
    }

    // ruleid: java-xpath-injection
    public String searchServlet(HttpServletRequest request) {
        String name = request.getParameter("name");
        XPath xpath = XPathFactory.newInstance().newXPath();
        return xpath.evaluate("//product[name='" + name + "']", doc);
    }

    // =========================================================================
    // TRUE NEGATIVES - Should NOT be detected
    // =========================================================================

    // ok: java-xpath-injection
    public String staticQuery() {
        // Safe: Hardcoded query
        XPath xpath = XPathFactory.newInstance().newXPath();
        return xpath.evaluate("//user[@admin='true']", doc);
    }

    // ok: java-xpath-injection
    public String hardcodedValues() {
        // Safe: Query with hardcoded values only
        XPath xpath = XPathFactory.newInstance().newXPath();
        String field = "status";
        String value = "active";
        return xpath.evaluate("//item[@" + field + "='" + value + "']", doc);
    }

    // ok: java-xpath-injection
    public String literalQuery() {
        // Safe: All literals
        XPath xpath = XPathFactory.newInstance().newXPath();
        return xpath.evaluate("//config[@env='production']", doc);
    }
}
