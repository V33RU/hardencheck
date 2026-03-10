CREDENTIAL_PATTERNS = [
    (r'(?i)(?:^|[^a-z_])password\s*[=:]\s*["\']([^"\'$%{}<>\s]{4,})["\']', "hardcoded password"),
    (r'(?i)(?:^|[^a-z_])passwd\s*[=:]\s*["\']([^"\'$%{}<>\s]{4,})["\']', "hardcoded passwd"),
    (r'(?i)(?:^|[^a-z_])pwd\s*[=:]\s*["\']([^"\'$%{}<>\s]{4,})["\']', "hardcoded pwd"),
    (r'(?i)(?:^|[^a-z_])secret\s*[=:]\s*["\']([^"\'$%{}<>\s]{8,})["\']', "hardcoded secret"),
    (r'(?i)api[_-]?key\s*[=:]\s*["\']([a-zA-Z0-9_\-]{16,})["\']', "API key"),
    (r'(?i)apikey\s*[=:]\s*["\']([a-zA-Z0-9_\-]{16,})["\']', "API key"),
    (r'(?i)auth[_-]?token\s*[=:]\s*["\']([a-zA-Z0-9_\-]{16,})["\']', "auth token"),
    (r'(?i)access[_-]?token\s*[=:]\s*["\']([a-zA-Z0-9_\-]{16,})["\']', "access token"),
    (r'(?i)bearer\s*[=:]\s*["\']([a-zA-Z0-9_\-\.]{20,})["\']', "bearer token"),
    (r'(?i)aws[_-]?secret[_-]?access[_-]?key\s*[=:]\s*["\']([A-Za-z0-9/+=]{40})["\']', "AWS secret key"),
    (r'AKIA[0-9A-Z]{16}', "AWS access key ID"),
    (r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----', "embedded private key"),
    (r'["\']admin["\']\s*[,:]\s*["\']admin["\']', "default admin:admin"),
    (r'["\']root["\']\s*[,:]\s*["\']root["\']', "default root:root"),
    (r'["\']root["\']\s*[,:]\s*["\']toor["\']', "default root:toor"),
]

FALSE_POSITIVE_INDICATORS = {
    "get_", "set_", "fetch_", "read_", "load_", "parse_", "validate_",
    "check_", "verify_", "update_", "create_", "delete_", "handle_",
    "env.", "os.environ", "getenv", "process.env", "environ[",
    "config.", "settings.", "options.", "params.", "args.",
    "def ", "function ", "func ", "->", "return ", "class ",
    "const ", "let ", "var ", "private ", "public ", "protected ",
    "example", "sample", "demo", "test", "mock", "fake", "dummy",
    "todo", "fixme", "xxx", "placeholder", "your_", "my_",
    ": str", ": string", ": String", "String ", "str ", ": &str",
    "<string>", "std::string", "QString", "NSString",
    "/*", "*/", "<!--", "-->", "'''", '"""',
    "label=", "placeholder=", "hint=", "title=", "name=",
    "inputType=", "type=\"password\"", "type='password'",
    "schema", "validate", "required", "optional", "field",
    "{{", "}}", "{%", "%}", "<%", "%>", "${", "#{",
}

WEAK_PASSWORDS = {
    "admin", "password", "123456", "12345678", "root", "toor",
    "default", "guest", "user", "test", "pass", "1234",
    "qwerty", "letmein", "welcome", "monkey", "dragon",
}
