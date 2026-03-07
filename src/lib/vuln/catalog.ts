/**
 * VARIANT — Vulnerability Template Catalog
 *
 * Pre-built VulnDefinition templates for every major VulnCategory.
 * Level designers pick from this catalog instead of writing raw patches.
 *
 * Each template is a complete VulnDefinition with:
 * - File patches that transform safe code into vulnerable code
 * - Clues and red herrings for the player
 * - Detection triggers for objective checking
 * - MITRE ATT&CK mapping
 *
 * DESIGN: Templates target the 'generic-webapp' base codebase
 * and are compatible with wildcard (*) for easy reuse.
 */

import type { VulnDefinition } from './types';

// ── Catalog Interface ───────────────────────────────────────────

export interface VulnCatalog {
    /** Get a template by ID. */
    get(id: string): VulnDefinition | null;

    /** List all templates. */
    list(): readonly VulnDefinition[];

    /** List by category. */
    listByCategory(category: string): readonly VulnDefinition[];

    /** List by difficulty. */
    listByDifficulty(difficulty: string): readonly VulnDefinition[];

    /** List by MITRE technique. */
    listByMitreTechnique(techniqueId: string): readonly VulnDefinition[];

    /** Search by keyword. */
    search(query: string): readonly VulnDefinition[];

    /** Add a custom template. */
    add(vuln: VulnDefinition): void;

    /** Get stats. */
    getStats(): VulnCatalogStats;
}

export interface VulnCatalogStats {
    readonly totalVulns: number;
    readonly byCategory: Readonly<Record<string, number>>;
    readonly byDifficulty: Readonly<Record<string, number>>;
}

// ── Built-in Vulnerability Templates ────────────────────────────

function createBuiltinVulns(): VulnDefinition[] {
    return [
        // ── SQL Injection ───────────────────────────────────────
        {
            id: 'VART-0001', name: 'Login Form SQL Injection',
            description: 'Classic SQL injection in the login form. User input concatenated directly into SQL query.',
            category: 'sqli', difficulty: 'beginner',
            compatibleBases: ['*'],
            severity: 8.5,
            mitreTechniques: ['T1190'],
            cweIds: ['CWE-89'],
            tags: ['web', 'authentication', 'database', 'owasp-a03'],
            patches: [
                {
                    type: 'create', path: '/var/www/html/login.php',
                    content: [
                        '<?php',
                        '$db = new PDO("mysql:host=localhost;dbname=app", "app_user", "app_pass");',
                        '',
                        'if ($_SERVER["REQUEST_METHOD"] === "POST") {',
                        '    $username = $_POST["username"];',
                        '    $password = $_POST["password"];',
                        '',
                        '    // VULNERABLE: Direct string concatenation in SQL query',
                        '    $sql = "SELECT * FROM users WHERE username = \'" . $username . "\' AND password = \'" . $password . "\'";',
                        '    $result = $db->query($sql);',
                        '',
                        '    if ($result && $result->rowCount() > 0) {',
                        '        session_start();',
                        '        $_SESSION["user"] = $result->fetch(PDO::FETCH_ASSOC);',
                        '        header("Location: /dashboard.php");',
                        '    } else {',
                        '        echo "Invalid credentials";',
                        '    }',
                        '}',
                        '?>',
                        '<html><body>',
                        '<form method="POST">',
                        '  <input name="username" placeholder="Username">',
                        '  <input name="password" type="password" placeholder="Password">',
                        '  <button type="submit">Login</button>',
                        '</form>',
                        '</body></html>',
                    ].join('\n'),
                },
            ],
            clues: [
                { location: 'file', path: '/var/www/html/login.php', content: '// VULNERABLE: Direct string concatenation', visibility: 4 },
                { location: 'log', path: '/var/log/mysql/query.log', content: "SELECT * FROM users WHERE username = 'admin' AND password = 'test'", visibility: 3 },
            ],
            redHerrings: [
                { location: 'file', path: '/var/www/html/config.php', content: '// PDO error mode set to silent — errors are hidden', visibility: 3 },
            ],
            detection: {
                mode: 'any',
                triggers: [
                    { type: 'http', method: 'POST', path: '/login.php', bodyContains: "' OR ", responseCode: 302 },
                    { type: 'http', method: 'POST', path: '/login.php', bodyContains: "1'='1", responseCode: 302 },
                    { type: 'command', pattern: "sqlmap.*login\\.php" },
                ],
            },
        },
        {
            id: 'VART-0002', name: 'Search Endpoint Blind SQLi',
            description: 'Time-based blind SQL injection in a search endpoint. No visible output, but response timing leaks data.',
            category: 'sqli', difficulty: 'advanced',
            compatibleBases: ['*'],
            severity: 7.5,
            mitreTechniques: ['T1190'],
            cweIds: ['CWE-89'],
            tags: ['web', 'blind', 'time-based', 'database'],
            patches: [
                {
                    type: 'create', path: '/var/www/html/api/search.php',
                    content: [
                        '<?php',
                        'header("Content-Type: application/json");',
                        '$db = new PDO("mysql:host=localhost;dbname=app", "app_user", "app_pass");',
                        '',
                        '$query = $_GET["q"] ?? "";',
                        '// VULNERABLE: User input in ORDER BY clause (blind SQLi)',
                        '$sort = $_GET["sort"] ?? "name";',
                        '$sql = "SELECT id, name, description FROM products WHERE name LIKE \'%" . $query . "%\' ORDER BY " . $sort;',
                        '$result = $db->query($sql);',
                        'echo json_encode($result ? $result->fetchAll(PDO::FETCH_ASSOC) : []);',
                    ].join('\n'),
                },
            ],
            clues: [
                { location: 'file', path: '/var/www/html/api/search.php', content: 'ORDER BY " . $sort', visibility: 3 },
            ],
            detection: {
                mode: 'any',
                triggers: [
                    { type: 'http', method: 'GET', path: '/api/search.php', bodyContains: 'SLEEP(' },
                    { type: 'http', method: 'GET', path: '/api/search.php', bodyContains: 'BENCHMARK(' },
                ],
            },
        },

        // ── XSS ─────────────────────────────────────────────────
        {
            id: 'VART-0010', name: 'Reflected XSS in Search',
            description: 'User search input reflected directly in page without encoding.',
            category: 'xss', difficulty: 'beginner',
            compatibleBases: ['*'],
            severity: 6.1,
            mitreTechniques: ['T1189'],
            cweIds: ['CWE-79'],
            tags: ['web', 'reflected', 'owasp-a03'],
            patches: [
                {
                    type: 'create', path: '/var/www/html/search.php',
                    content: [
                        '<?php $query = $_GET["q"] ?? ""; ?>',
                        '<html><body>',
                        '<h1>Search Results</h1>',
                        '<!-- VULNERABLE: No output encoding -->',
                        '<p>Results for: <?php echo $query; ?></p>',
                        '<p>No results found.</p>',
                        '</body></html>',
                    ].join('\n'),
                },
            ],
            clues: [
                { location: 'file', path: '/var/www/html/search.php', content: 'echo $query', visibility: 4 },
            ],
            detection: {
                mode: 'any',
                triggers: [
                    { type: 'http', method: 'GET', path: '/search.php', bodyContains: '<script>' },
                    { type: 'http', method: 'GET', path: '/search.php', bodyContains: 'onerror=' },
                ],
            },
        },
        {
            id: 'VART-0011', name: 'Stored XSS in Comments',
            description: 'Comment system stores user input and renders it without sanitization.',
            category: 'xss', difficulty: 'intermediate',
            compatibleBases: ['*'],
            severity: 7.2,
            mitreTechniques: ['T1189'],
            cweIds: ['CWE-79'],
            tags: ['web', 'stored', 'persistent', 'owasp-a03'],
            patches: [
                {
                    type: 'create', path: '/var/www/html/comments.php',
                    content: [
                        '<?php',
                        '$db = new PDO("mysql:host=localhost;dbname=app", "app_user", "app_pass");',
                        'if ($_SERVER["REQUEST_METHOD"] === "POST") {',
                        '    // VULNERABLE: Stored without sanitization',
                        '    $stmt = $db->prepare("INSERT INTO comments (body, author) VALUES (?, ?)");',
                        '    $stmt->execute([$_POST["body"], $_POST["author"]]);',
                        '}',
                        '$comments = $db->query("SELECT * FROM comments ORDER BY id DESC")->fetchAll();',
                        '?>',
                        '<html><body>',
                        '<?php foreach ($comments as $c): ?>',
                        '  <!-- VULNERABLE: No output encoding -->',
                        '  <div class="comment"><b><?php echo $c["author"]; ?></b>: <?php echo $c["body"]; ?></div>',
                        '<?php endforeach; ?>',
                        '</body></html>',
                    ].join('\n'),
                },
            ],
            clues: [
                { location: 'file', path: '/var/www/html/comments.php', content: 'echo $c["body"]', visibility: 3 },
            ],
            detection: {
                mode: 'any',
                triggers: [
                    { type: 'http', method: 'POST', path: '/comments.php', bodyContains: '<script>' },
                    { type: 'http', method: 'POST', path: '/comments.php', bodyContains: 'javascript:' },
                ],
            },
        },

        // ── RCE ─────────────────────────────────────────────────
        {
            id: 'VART-0020', name: 'Command Injection in Ping Utility',
            description: 'Network diagnostic page passes user input directly to system() call.',
            category: 'rce', difficulty: 'beginner',
            compatibleBases: ['*'],
            severity: 9.8,
            mitreTechniques: ['T1059', 'T1190'],
            cweIds: ['CWE-78'],
            tags: ['web', 'command-injection', 'system-call', 'owasp-a03'],
            patches: [
                {
                    type: 'create', path: '/var/www/html/ping.php',
                    content: [
                        '<?php',
                        'if ($_SERVER["REQUEST_METHOD"] === "POST") {',
                        '    $host = $_POST["host"];',
                        '    // VULNERABLE: Direct command injection',
                        '    $output = shell_exec("ping -c 3 " . $host);',
                        '    echo "<pre>" . $output . "</pre>";',
                        '}',
                        '?>',
                        '<html><body>',
                        '<h1>Network Diagnostic</h1>',
                        '<form method="POST">',
                        '  <input name="host" placeholder="Enter hostname or IP">',
                        '  <button>Ping</button>',
                        '</form>',
                        '</body></html>',
                    ].join('\n'),
                },
            ],
            clues: [
                { location: 'file', path: '/var/www/html/ping.php', content: 'shell_exec("ping -c 3 " . $host)', visibility: 4 },
            ],
            detection: {
                mode: 'any',
                triggers: [
                    { type: 'http', method: 'POST', path: '/ping.php', bodyContains: ';' },
                    { type: 'http', method: 'POST', path: '/ping.php', bodyContains: '|' },
                    { type: 'command', pattern: 'ping.*&&|ping.*\\|' },
                ],
            },
        },
        {
            id: 'VART-0021', name: 'Deserialization RCE',
            description: 'PHP unserialize() on user-controlled input enables object injection.',
            category: 'deserialization', difficulty: 'expert',
            compatibleBases: ['*'],
            severity: 9.0,
            mitreTechniques: ['T1059', 'T1203'],
            cweIds: ['CWE-502'],
            tags: ['web', 'php', 'object-injection', 'gadget-chain'],
            patches: [
                {
                    type: 'create', path: '/var/www/html/profile.php',
                    content: [
                        '<?php',
                        'class UserPrefs {',
                        '    public $theme = "default";',
                        '    public $lang = "en";',
                        '    public function __destruct() {',
                        '        // Cleanup: log preferences change',
                        '        file_put_contents("/tmp/prefs.log", $this->theme . "\\n", FILE_APPEND);',
                        '    }',
                        '}',
                        '',
                        '// VULNERABLE: Unserialize user cookie',
                        '$prefs = isset($_COOKIE["prefs"]) ? unserialize($_COOKIE["prefs"]) : new UserPrefs();',
                        'echo "Theme: " . htmlspecialchars($prefs->theme);',
                        '?>',
                    ].join('\n'),
                },
            ],
            clues: [
                { location: 'file', path: '/var/www/html/profile.php', content: 'unserialize($_COOKIE["prefs"])', visibility: 3 },
            ],
            detection: {
                mode: 'any',
                triggers: [
                    { type: 'http', method: 'GET', path: '/profile.php', bodyContains: 'O:' },
                    { type: 'file:write', path: '/tmp/prefs.log', contentContains: '../' },
                ],
            },
        },

        // ── SSRF ────────────────────────────────────────────────
        {
            id: 'VART-0030', name: 'SSRF via URL Preview',
            description: 'URL preview feature fetches arbitrary URLs, including internal services.',
            category: 'ssrf', difficulty: 'intermediate',
            compatibleBases: ['*'],
            severity: 8.0,
            mitreTechniques: ['T1190', 'T1552'],
            cweIds: ['CWE-918'],
            tags: ['web', 'ssrf', 'internal-network', 'cloud-metadata'],
            patches: [
                {
                    type: 'create', path: '/var/www/html/preview.php',
                    content: [
                        '<?php',
                        'header("Content-Type: application/json");',
                        '$url = $_GET["url"] ?? "";',
                        'if (empty($url)) { echo json_encode(["error" => "No URL"]); exit; }',
                        '',
                        '// VULNERABLE: No URL validation, fetches any URL including internal',
                        '$content = file_get_contents($url);',
                        'echo json_encode([',
                        '    "url" => $url,',
                        '    "content" => substr($content, 0, 1000),',
                        '    "length" => strlen($content)',
                        ']);',
                    ].join('\n'),
                },
            ],
            clues: [
                { location: 'file', path: '/var/www/html/preview.php', content: 'file_get_contents($url)', visibility: 3 },
            ],
            detection: {
                mode: 'any',
                triggers: [
                    { type: 'http', method: 'GET', path: '/preview.php', bodyContains: '169.254.169.254' },
                    { type: 'http', method: 'GET', path: '/preview.php', bodyContains: 'localhost' },
                    { type: 'http', method: 'GET', path: '/preview.php', bodyContains: '127.0.0.1' },
                ],
            },
        },

        // ── Path Traversal ──────────────────────────────────────
        {
            id: 'VART-0040', name: 'File Download Path Traversal',
            description: 'File download endpoint with no path validation, allowing access to any file.',
            category: 'path-traversal', difficulty: 'beginner',
            compatibleBases: ['*'],
            severity: 7.5,
            mitreTechniques: ['T1005'],
            cweIds: ['CWE-22'],
            tags: ['web', 'lfi', 'file-read', 'owasp-a01'],
            patches: [
                {
                    type: 'create', path: '/var/www/html/download.php',
                    content: [
                        '<?php',
                        '$file = $_GET["file"] ?? "";',
                        '// VULNERABLE: No path validation',
                        '$path = "/var/www/html/uploads/" . $file;',
                        'if (file_exists($path)) {',
                        '    header("Content-Type: application/octet-stream");',
                        '    header("Content-Disposition: attachment; filename=" . basename($file));',
                        '    readfile($path);',
                        '} else {',
                        '    http_response_code(404);',
                        '    echo "File not found";',
                        '}',
                    ].join('\n'),
                },
            ],
            clues: [
                { location: 'file', path: '/var/www/html/download.php', content: '"/var/www/html/uploads/" . $file', visibility: 4 },
            ],
            detection: {
                mode: 'any',
                triggers: [
                    { type: 'http', method: 'GET', path: '/download.php', bodyContains: '../' },
                    { type: 'file:read', path: '/etc/passwd' },
                    { type: 'file:read', path: '/etc/shadow' },
                ],
            },
        },

        // ── Auth Bypass ─────────────────────────────────────────
        {
            id: 'VART-0050', name: 'JWT None Algorithm Bypass',
            description: 'JWT validation accepts "none" algorithm, allowing token forgery.',
            category: 'jwt-bypass', difficulty: 'intermediate',
            compatibleBases: ['*'],
            severity: 9.0,
            mitreTechniques: ['T1550', 'T1134'],
            cweIds: ['CWE-345', 'CWE-327'],
            tags: ['web', 'jwt', 'authentication', 'token-forgery'],
            patches: [
                {
                    type: 'create', path: '/var/www/html/api/auth.js',
                    content: [
                        "const jwt = require('jsonwebtoken');",
                        "const SECRET = 'app_secret_key_2024';",
                        '',
                        'function verifyToken(token) {',
                        '    // VULNERABLE: algorithms not restricted, accepts "none"',
                        '    return jwt.verify(token, SECRET);',
                        '}',
                        '',
                        'function generateToken(userId, role) {',
                        '    return jwt.sign({ userId, role }, SECRET, { algorithm: "HS256", expiresIn: "1h" });',
                        '}',
                        '',
                        'module.exports = { verifyToken, generateToken };',
                    ].join('\n'),
                },
            ],
            clues: [
                { location: 'file', path: '/var/www/html/api/auth.js', content: 'algorithms not restricted', visibility: 3 },
            ],
            detection: {
                mode: 'any',
                triggers: [
                    { type: 'http', method: 'GET', path: '/api/', bodyContains: 'eyJhbGciOiJub25lI' },
                    { type: 'custom', eventType: 'jwt-bypass', match: { algorithm: 'none' } },
                ],
            },
        },

        // ── IDOR ────────────────────────────────────────────────
        {
            id: 'VART-0060', name: 'IDOR in User Profile API',
            description: 'API endpoint uses sequential user IDs with no authorization check.',
            category: 'idor', difficulty: 'beginner',
            compatibleBases: ['*'],
            severity: 6.5,
            mitreTechniques: ['T1078'],
            cweIds: ['CWE-639'],
            tags: ['web', 'api', 'authorization', 'owasp-a01'],
            patches: [
                {
                    type: 'create', path: '/var/www/html/api/user.php',
                    content: [
                        '<?php',
                        'session_start();',
                        'header("Content-Type: application/json");',
                        '',
                        '$userId = $_GET["id"] ?? null;',
                        '// VULNERABLE: No authorization check — any authenticated user can access any profile',
                        'if (!isset($_SESSION["user"])) { http_response_code(401); echo "{}"; exit; }',
                        '',
                        '$db = new PDO("mysql:host=localhost;dbname=app", "app_user", "app_pass");',
                        '$stmt = $db->prepare("SELECT id, username, email, role FROM users WHERE id = ?");',
                        '$stmt->execute([$userId]);',
                        'echo json_encode($stmt->fetch(PDO::FETCH_ASSOC));',
                    ].join('\n'),
                },
            ],
            clues: [
                { location: 'file', path: '/var/www/html/api/user.php', content: 'No authorization check', visibility: 3 },
            ],
            detection: {
                mode: 'any',
                triggers: [
                    { type: 'http', method: 'GET', path: '/api/user.php', bodyContains: 'id=1' },
                    { type: 'http', method: 'GET', path: '/api/user.php', bodyContains: 'id=2' },
                ],
            },
        },

        // ── Privilege Escalation ────────────────────────────────
        {
            id: 'VART-0070', name: 'Sudo Misconfiguration (NOPASSWD)',
            description: 'User can run specific commands as root without password via sudo misconfig.',
            category: 'privesc', difficulty: 'intermediate',
            compatibleBases: ['*'],
            severity: 8.0,
            mitreTechniques: ['T1548.003'],
            cweIds: ['CWE-269'],
            tags: ['linux', 'sudo', 'privesc', 'gtfobins'],
            patches: [
                {
                    type: 'create', path: '/etc/sudoers.d/webapp',
                    content: [
                        '# Allow webapp user to restart services',
                        '# VULNERABLE: vim allows shell escape → root',
                        'www-data ALL=(root) NOPASSWD: /usr/bin/vim /var/log/webapp/*',
                        'www-data ALL=(root) NOPASSWD: /usr/bin/find /var/www/ -name *.log',
                    ].join('\n'),
                    mode: 0o440,
                },
            ],
            clues: [
                { location: 'file', path: '/etc/sudoers.d/webapp', content: 'NOPASSWD: /usr/bin/vim', visibility: 3 },
            ],
            detection: {
                mode: 'any',
                triggers: [
                    { type: 'command', pattern: 'sudo\\s+vim|sudo\\s+-u\\s+root\\s+vim' },
                    { type: 'command', pattern: 'sudo\\s+find.*-exec' },
                ],
            },
        },

        // ── Hardcoded Credentials ───────────────────────────────
        {
            id: 'VART-0080', name: 'Hardcoded API Keys in Source',
            description: 'Third-party API keys and secrets hardcoded in application source code.',
            category: 'hardcoded-creds', difficulty: 'beginner',
            compatibleBases: ['*'],
            severity: 7.0,
            mitreTechniques: ['T1552.001'],
            cweIds: ['CWE-798'],
            tags: ['credentials', 'api-keys', 'secrets', 'source-code'],
            patches: [
                {
                    type: 'create', path: '/var/www/html/config/services.php',
                    content: [
                        '<?php',
                        '// Service configuration',
                        'return [',
                        "    'stripe' => [",
                        "        'secret_key' => 'sk_test_VARIANT_FAKE_4eC39HqLyjWDarj',",
                        "        'publishable_key' => 'pk_test_VARIANT_FAKE_TYooMQauvdEDq54',",
                        '    ],',
                        "    'sendgrid' => [",
                        "        'api_key' => 'SG.1234567890abcdef.xyzXYZ',",
                        '    ],',
                        "    'aws' => [",
                        "        'access_key' => 'AKIAIOSFODNN7EXAMPLE',",
                        "        'secret_key' => 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',",
                        "        'region' => 'us-east-1',",
                        '    ],',
                        '];',
                    ].join('\n'),
                },
            ],
            clues: [
                { location: 'file', path: '/var/www/html/config/services.php', content: 'sk_test_VARIANT_', visibility: 4 },
                { location: 'log', path: '/var/log/git.log', content: 'commit abc123: "added service configs" — config/services.php', visibility: 2 },
            ],
            detection: {
                mode: 'any',
                triggers: [
                    { type: 'file:read', path: '/var/www/html/config/services.php' },
                    { type: 'command', pattern: 'grep.*sk_test_VARIANT|grep.*AKIA|grep.*SG\\.' },
                ],
            },
        },

        // ── Information Leak ────────────────────────────────────
        {
            id: 'VART-0090', name: 'Git Repository Exposed',
            description: '.git directory accessible via web server, exposing source code and commit history.',
            category: 'info-leak', difficulty: 'intermediate',
            compatibleBases: ['*'],
            severity: 7.5,
            mitreTechniques: ['T1213', 'T1552.001'],
            cweIds: ['CWE-538'],
            tags: ['web', 'git', 'source-code', 'enumeration'],
            patches: [
                {
                    type: 'create', path: '/var/www/html/.git/HEAD',
                    content: 'ref: refs/heads/main\n',
                },
                {
                    type: 'create', path: '/var/www/html/.git/config',
                    content: [
                        '[core]', '    repositoryformatversion = 0', '    filemode = true',
                        '[remote "origin"]', '    url = git@github.com:company/webapp.git',
                        '    fetch = +refs/heads/*:refs/remotes/origin/*',
                    ].join('\n'),
                },
                {
                    type: 'create', path: '/var/www/html/.git/logs/HEAD',
                    content: [
                        '0000000 abc1234 Dev <dev@company.com> 1705334400 +0000\tcommit (initial): initial commit',
                        'abc1234 def5678 Dev <dev@company.com> 1705334500 +0000\tcommit: added database config with credentials',
                        'def5678 ghi9012 Dev <dev@company.com> 1705334600 +0000\tcommit: removed credentials (oops)',
                    ].join('\n'),
                },
            ],
            clues: [
                { location: 'log', path: '/var/log/nginx/access.log', content: '10.0.1.5 - - [15/Jan/2024:10:22:33 +0000] "GET /.git/HEAD HTTP/1.1" 200 23', visibility: 3 },
            ],
            detection: {
                mode: 'any',
                triggers: [
                    { type: 'file:read', path: '/var/www/html/.git/HEAD' },
                    { type: 'http', method: 'GET', path: '/.git/HEAD' },
                    { type: 'command', pattern: 'git.*log|git.*show|git.*diff' },
                ],
            },
        },
    ];
}

// ── Factory ─────────────────────────────────────────────────────

export function createVulnCatalog(): VulnCatalog {
    const vulns = new Map<string, VulnDefinition>();

    for (const v of createBuiltinVulns()) {
        vulns.set(v.id, Object.freeze(v));
    }

    return {
        get(id: string): VulnDefinition | null {
            return vulns.get(id) ?? null;
        },

        list(): readonly VulnDefinition[] {
            return Object.freeze([...vulns.values()]);
        },

        listByCategory(category: string): readonly VulnDefinition[] {
            return Object.freeze(
                [...vulns.values()].filter(v => v.category === category)
            );
        },

        listByDifficulty(difficulty: string): readonly VulnDefinition[] {
            return Object.freeze(
                [...vulns.values()].filter(v => v.difficulty === difficulty)
            );
        },

        listByMitreTechnique(techniqueId: string): readonly VulnDefinition[] {
            return Object.freeze(
                [...vulns.values()].filter(v =>
                    v.mitreTechniques !== undefined && v.mitreTechniques.includes(techniqueId)
                )
            );
        },

        search(query: string): readonly VulnDefinition[] {
            const lower = query.toLowerCase();
            return Object.freeze(
                [...vulns.values()].filter(v =>
                    v.id.toLowerCase().includes(lower) ||
                    v.name.toLowerCase().includes(lower) ||
                    v.description.toLowerCase().includes(lower) ||
                    (v.tags ?? []).some(t => t.toLowerCase().includes(lower))
                )
            );
        },

        add(vuln: VulnDefinition): void {
            vulns.set(vuln.id, Object.freeze(vuln));
        },

        getStats(): VulnCatalogStats {
            const byCategory: Record<string, number> = {};
            const byDifficulty: Record<string, number> = {};

            for (const v of vulns.values()) {
                byCategory[v.category] = (byCategory[v.category] ?? 0) + 1;
                byDifficulty[v.difficulty] = (byDifficulty[v.difficulty] ?? 0) + 1;
            }

            return Object.freeze({ totalVulns: vulns.size, byCategory, byDifficulty });
        },
    };
}
