<?php
// Test cases for php-xpath-injection rule

// =============================================================================
// TRUE POSITIVES - Should be detected
// =============================================================================

// ruleid: php-xpath-injection
function login_vulnerable() {
    $username = $_POST['username'];
    $password = $_POST['password'];
    $xml = simplexml_load_file('users.xml');
    $result = $xml->xpath("//user[username='$username' and password='$password']");
    return count($result) > 0;
}

// ruleid: php-xpath-injection
function search_vulnerable() {
    $name = $_GET['name'];
    $xml = simplexml_load_file('products.xml');
    $query = "//product[name='" . $name . "']";
    return $xml->xpath($query);
}

// ruleid: php-xpath-injection
function domxpath_vulnerable() {
    $id = $_REQUEST['id'];
    $doc = new DOMDocument();
    $doc->load('data.xml');
    $xpath = new DOMXPath($doc);
    return $xpath->query("//item[@id='$id']");
}

// ruleid: php-xpath-injection
function laravel_vulnerable(Request $request) {
    $category = $request->input('category');
    $xml = simplexml_load_string($data);
    return $xml->xpath("//product[@category='$category']");
}

// =============================================================================
// TRUE NEGATIVES - Should NOT be detected
// =============================================================================

// ok: php-xpath-injection
function static_query() {
    // Safe: Hardcoded query
    $xml = simplexml_load_file('users.xml');
    return $xml->xpath("//user[@admin='true']");
}

// ok: php-xpath-injection
function hardcoded_values() {
    // Safe: Query with hardcoded values only
    $xml = simplexml_load_file('config.xml');
    $field = "status";
    $value = "active";
    return $xml->xpath("//setting[@$field='$value']");
}

// ok: php-xpath-injection
function literal_query() {
    // Safe: All literals, no variables at all
    $xml = simplexml_load_file('data.xml');
    return $xml->xpath("//item[@type='product' and @active='1']");
}
?>
