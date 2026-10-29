# Wordpress Security Audit

## Project Purpose & Motivation

### About the Project
The main goal of this project is to **gather and organize security auditing tools specifically for WordPress websites**. To simplify the installation process (and for my own convenience), all of these tools are pre-packaged and contained within a **Docker image**.

### Author's Note
Please note that **I am not a cybersecurity expert or a professional security auditor**. I am an experienced web developer who noticed a lack of easily accessible, up-to-date tools for detecting and analyzing this specific type of malware injection. 

Out of concern for this gap in the community, I decided to build this utility using my web development experience. While I have put my best efforts into making it useful and accurate, this project should be treated as a developer's helper tool rather than a certified enterprise security solution. If you require absolute security guarantees, you should always consult with a professional cybersecurity firm.

---

## Limitation of Liability & Disclaimer

### 1. Use at Your Own Risk
This software and the contained tools are provided solely for informational, educational, and assistance purposes in detecting potential malware injections in WordPress environments. The user assumes all responsibility and risk associated with the use of this Docker image.

### 2. "As-Is" Warranty
The software is provided "as is" and "as available", without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, and noninfringement. There is no guarantee that the tools will be uninterrupted, error-free, 100% accurate, or capable of detecting all types of malware, web shells, or vulnerabilities.

### 3. Limitation of Liability
In no event shall the authors, developers, or copyright holders be liable for any claim, damages, or other liability—whether in an action of contract, tort, or otherwise—arising from, out of, or in connection with the software, the Docker container, or the use of these tools. This includes, but is not limited to, loss of data, website downtime, profits, or business interruption caused by missed threats or false positives.

### 4. Environment Recommendation
Given the nature of malware analysis and security auditing, it is highly recommended to run this Docker container exclusively within isolated test environments or staging copies of your sites. The user is solely responsible for maintaining comprehensive backups of all databases and WordPress files prior to execution.

---

## Base documentation

### Build and use the Docker image

This project is packaged as a Docker image that contains the YARA rules and the helper scripts needed to scan a WordPress installation.

From the project root:

```bash
docker build -t wordpress-security-audit .
```

It is important to keep in mind that YARA-based malware detection is inherently prone to false positives: a suspicious pattern may also appear in legitimate custom code, common PHP idioms, or site-specific implementations. For this reason, the project supports custom rule sets and uses a mounted volume for the rules directory so each site can maintain its own curated whitelist and tuned signatures.

To scan a site directory, mount both the WordPress root and the rules directory into the container and run the scanner:

```bash
docker run --rm \
  -v "$PWD/volumes/www:/var/www/html:ro" \
  -v "$PWD/volumes/yara-rules:/usr/share/yara-rules:ro" \
  wordpress-security-audit \
  yara -r /usr/share/yara-rules/php.yar /var/www/html
```

The `docker-compose.yml` file does exactly this for the project workflow, mounting the YARA rule set as a separate volume so you can customize or extend the whitelist without modifying the image itself.

The image also exposes the helper scripts under `/usr/local/bin/`, so they can be executed directly inside the container as needed.

For a more beginner-friendly explanation of the security concepts behind YARA, false positives, non-printable characters, and whitelist-based filtering, see [security-for-dummies.md](security-for-dummies.md).

### Script 1: `generate-whitelist.sh`

Purpose:
- Detect the WordPress version installed in `/var/www/html`
- Download the corresponding official WordPress package from WordPress.org when needed
- Generate YARA whitelist rules for:
  - WordPress core files
  - Installed plugins
  - Installed themes

How to use it:

```bash
docker compose run --rm wsa /usr/local/bin/generate-whitelist.sh
```

This is the recommended workflow for the project because the compose file mounts the custom rule directory in `/usr/share/yara-rules`, allowing the generated whitelist to be reused across scans without rewriting the image or the base ruleset.

This script reads the WordPress files in `/var/www/html`, extracts the plugin/theme metadata (`Plugin Name:`, `Theme Name:`, `Version:`), downloads the matching official packages, and generates hash-based whitelist rules to reduce false positives when scanning for malicious code.

### Script 2: `sanitize-yara-matched-images.sh`

Purpose:
- Scan the WordPress tree for files flagged by the YARA rules
- Filter only real image files using `identify`
- Rewrite the image binary in-place with a safe transformation (`-flip -flip` / re-encode) to break malicious payload alignment without changing the visible image too much
- Output the sanitized image hashes as YARA whitelist entries

How to use it:

```bash
docker run --rm \
  -v "$PWD/volumes/www:/var/www/html:rw" \
  -v "$PWD/volumes/yara-rules:/usr/share/yara-rules:ro" \
  wordpress-security-audit \
  /usr/local/bin/sanitize-yara-matched-images.sh
```

This is the sanitization step for suspicious image files found in the site tree. It must be executed with write access to the target `wwwroot` because it modifies the files in place. The rule volume is still important here because the sanitization step is meant to complement a curated YARA rule set and a whitelist-based workflow rather than relying on a single broad pattern.

> Warning: always work on a backup or an isolated copy of the site before applying sanitization to production files.

> Note: The problem of detecting injected code within media files is highly complex. Therefore, to solve this issue, we will choose to sanitize and reconstruct the image while strictly preserving its original visual appearance. To achieve this, we will apply a double vertical flip operation (`-flip -flip`). This technique forces the graphics engine to completely rewrite the underlying binary stream and compression structures, breaking the malware's alignment without altering the dimensions or color indexing of the file.

---

## TODO

* [ ] Search for installed malware:
  * [ ] Site code **In progress**
  * [ ] Data / Database
* [ ] Check for vulnerabilities in installed WordPress versions, plugins, and themes
