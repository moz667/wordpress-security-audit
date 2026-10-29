# Security for dummies

This document is intended as a very practical, beginner-friendly guide to some of the most common security concepts that appear during WordPress malware analysis.

The goal is not to turn this project into a cybersecurity course, but to help a developer with a web background understand why some patterns are suspicious, why false positives happen, and how to think about risk in a calm and systematic way.

---

## 1) Why a WordPress site can be infected even when it looks normal

A WordPress site usually contains:

- PHP code
- JavaScript
- CSS
- plugins and themes
- database content
- uploaded files
- media files

Any of these can be modified by malware. Sometimes the malicious payload is obvious. Sometimes it is hidden in:

- compressed or encoded strings
- base64 payloads
- weird file names
- images with embedded code
- functions that look legitimate but are abused in a suspicious way

This is exactly why scanning tools must be careful. A pattern can look suspicious in one context and totally normal in another.

---

## 2) Why false positives are normal in malware analysis

A YARA rule searches for patterns. That is useful, but it has a problem: patterns are not always unique.

For example, many legitimate WordPress plugins or themes contain strings such as:

- `base64_decode`
- `eval`
- `file_get_contents`
- `curl`
- `preg_replace`
- `wp_remote_get`
- `http_build_query`

These are totally normal in regular code. But a malicious script may also use them.

So the real question is not just:

- “Does this code use `eval`?”

The real question is:

- “Is this `eval` used in a malicious or suspicious way in this specific context?”

That is why you often need:

- custom YARA rules
- custom whitelists
- site-specific exclusions
- manual review of the final matches

This project tries to reduce the noise by:

- generating whitelist hashes for official WordPress core files
- generating whitelist hashes for official plugins and themes
- only processing entries that match the YARA rules
- limiting metadata searches to the relevant header files

---

## 3) What are non-printable characters and why do they matter?

Non-printable characters are bytes that are not meant to be displayed normally in text. Examples include:

- NUL bytes (`\x00`)
- carriage returns (`\r`)
- line feeds (`\n`)
- tab characters (`\t`)
- control characters like `\x1f`, `\x7f`, `\x1b`
- malformed UTF-8 sequences

These bytes are not “bad” by themselves. The danger is when they appear where they should not, especially in:

- HTTP headers
- file contents
- script output
- uploaded files
- SQL queries
- shell commands
- configuration files

They can be used to:

- break parsing
- confuse regex or sanitizers
- hide malicious code behind a benign-looking file
- bypass simple detection rules
- alter the output of a response or a script

---

## 4) Real-world examples of dangerous non-printable characters

### Example 1: header injection

```php
header("Location: /login.php\r\nSet-Cookie: admin=true");
```

This is dangerous because `\r\n` is a carriage return + newline. If it reaches the HTTP response layer without validation, an attacker may inject extra headers or modify the response flow.

This is a classic response splitting / header injection vector.

### Example 2: NUL byte in a string

```php
$raw = "admin\x00";
```

A parser or function may treat this as the end of the string, or it may behave differently depending on the runtime or library used. This can confuse validation, logging, and comparisons.

### Example 3: weird bytes hidden in uploaded files

A malicious file may look like an image or text file but also contain control bytes inside the payload. A scanner may only inspect the first few bytes and miss the suspicious content later in the file.

This is one of the reasons why sanitizing image files can be useful in malware analysis: a malicious payload may be hidden in a file that looks harmless at first glance.

### Example 4: bypass of filters or regex

```php
if (preg_match('/^[a-zA-Z0-9]+$/', $user)) {
    // allow
}
```

If an attacker can smuggle a control character or a Unicode surrogate-like byte sequence, the value may appear harmless to one layer and then be interpreted differently by another part of the application.

This is a common bypass technique.

### Example 5: shell or SQL confusion

```php
$query = "SELECT * FROM users WHERE name = 'admin\x00'";
```

Depending on the database driver and the environment, these bytes may change the meaning of the query or break expectations in ways that are hard to debug.

---

## 5) Why this matters in WordPress malware analysis

WordPress plugins and themes are PHP projects running in a PHP environment. They often contain:

- loops
- strings
- concatenations
- file system access
- network calls
- dynamic evaluation
- obfuscated code

Because of that, malware not only needs to be suspicious; it also needs to be context-aware.

A piece of code can be legitimate in one file and malicious in another because:

- it is loaded in a different context
- it is executed under a different trigger
- it is combined with other strings or functions
- it is hidden behind encoding or concatenation

This is why a robust audit process usually uses:

- multiple YARA rules
- whitelist generation for trusted software
- manual inspection of suspicious paths
- checks on the file header and metadata
- validation of the plugin or theme version before trying to download the official package

---

## 6) Why we limit searches to the real plugin/theme header

This project tries to avoid false positives by looking only at the relevant metadata fields in the relevant files.

For example:

- plugin metadata usually lives in the main plugin PHP file
- theme metadata usually lives in `style.css`
- the version and name are expected near the top of that file

So we avoid scanning the whole plugin directory for `Version:` because a plugin may contain other files such as:

- `license.txt`
- HTML release logs
- translator files
- readme documents
- example data

Those files can easily contain text like:

- `Version 3, 29 June 2007`
- `Version 6.5.14 (6th January 2022)`

This is completely different from the actual WordPress plugin version in the plugin header and would become a false positive if we searched the entire directory blindly.

This is the main reason behind the method used in this project:

- scan with YARA
- take only the directories that match
- inspect the header of the plugin/theme only
- read only the beginning of the header file
- extract the real version metadata

---

## 7) Why whitelists are so important

A whitelist is a list of known-good code or hashes that helps avoid flagging legitimate files as malicious.

For a WordPress project, this is especially useful because many plugins and themes are common and may contain code patterns that resemble malware under a naive rule.

The whitelist workflow usually works like this:

1. identify the WordPress version
2. identify the plugin/theme set in use
3. download the official package from the official repository
4. generate hashes for the trusted files
5. compare those hashes against the site data
6. ignore or reduce matches that correspond to known good code

This is not a magic shield, but it is a very effective way to reduce noise and improve the quality of the review.

---

## 8) The mindset to keep

When auditing code for security, it helps to remember:

- unusual patterns are not automatically malicious
- normal code can be abused in malicious ways
- false positives are a normal part of static scanning
- context is more important than the string itself
- the safest approach is usually layered: scan, narrow, inspect, validate

Security is not about finding one magical signature. It is about understanding how code is used, where it is loaded, and how it interacts with the rest of the system.

---

## 9) Practical takeaway

For a WordPress site, the usual workflow is:

- scan the site with YARA
- identify the suspicious files and directories
- narrow the scope to the real plugin/theme root
- inspect the main metadata file only
- compare against official plugin/theme packages
- whitelist known-good files
- manually review the remaining suspicious matches

This is a pragmatic, developer-friendly way to avoid overreacting to noise while still catching actual suspicious code.

---

## 10) Final note

This project is intentionally aimed at people who are not cybersecurity experts but who need a practical tool to review a WordPress site with a bit more clarity.

It is not a full forensic suite, and it is not a substitute for professional review in high-risk environments. But it can still be very useful as a helper to narrow down suspicious patterns and focus the investigation on the right places.
