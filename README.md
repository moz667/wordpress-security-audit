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

The default `wsa` command runs `wsa-scan.sh`. To run its optional preparation steps before the final YARA scan, use:

```bash
docker compose run --rm -T wsa wsa-scan.sh --auto-add-to-whitelist
docker compose run --rm -T wsa wsa-scan.sh --sanitize-images
docker compose run --rm -T wsa wsa-scan.sh --all
docker compose run --rm -T wsa wsa-scan.sh --verbose
```

`--all` runs automatic official and third-party whitelist generation, then image sanitization, followed by the final scan. Work on an isolated copy when enabling image sanitization.

Use `--verbose` (or `-v`) to show the matched strings and their offsets in addition to the matching rule and file.

For a more beginner-friendly explanation of the security concepts behind YARA, false positives, non-printable characters, and whitelist-based filtering, see [security-for-dummies.md](security-for-dummies.md).

### Script 1: `wsa-auto-add-to-whitelists.sh`

Purpose:
- Detect the WordPress version installed in `/var/www/html`
- Process every ZIP in the curated third-party volume, including packages not installed in the audited site
- Resolve official WordPress, plugin and theme packages for installed files that trigger `php.yar`
- Generate hash rules for matching files from those reference packages:
  - WordPress core files
  - Installed plugins
  - Installed themes

Run the generator to persist each validated rule block as it is generated:

```bash
docker compose run --rm -T wsa /usr/local/bin/wsa-auto-add-to-whitelists.sh
```

To preview changes without writing them:

```bash
docker compose run --rm -T wsa /usr/local/bin/wsa-auto-add-to-whitelists.sh --dry-run
```

Progress and a concise summary are printed to stderr. Hash rules are stored in the mounted whitelist files rather than printed to stdout. If a package cannot be resolved, processing continues and already validated rules remain saved. After the summary, the script lists unavailable resources with their type, slug/version, and download URL. Unresolved files or package errors cause a non-zero exit status.

The whitelist rules are currently organized by source and confidence:

- `yara-rules/whitelists/10-oficial-repository.yar` — files verified against the official WordPress repository.
- `yara-rules/whitelists/20-third-party.yar` — packages from the curated third-party volume, including plugins and themes.
- `yara-rules/whitelists/99-custom.yar` — manually validated exceptions, including custom rules for image false positives.

Rules from ZIPs in `./volumes/third-party` go to `20-third-party.yar`. Rules from the WordPress.org repository, including archives downloaded and stored in the cache by this script, go to `10-oficial-repository.yar`. The cache is reserved for these official downloads. Manually validated exceptions remain in `99-custom.yar`. At the end of a run, `last_updated` is refreshed once in each generated whitelist that received new rules; `--dry-run` does not change timestamps.

The script reads plugin and theme metadata (`Plugin Name:`, `Theme Name:`, `Version:`) from the installed site and resolves matching packages using the fallback chain below. The main plugin file is the PHP file in its root directory with a `Plugin Name:` header in its first 20 lines; theme metadata is read from `style.css`. Only installed packages with YARA findings are resolved this way. Third-party ZIPs are cataloged separately whether or not they are installed.

Before saving each block, the script validates the candidate YARA rules. It then rescans every file reported by the initial site scan. Any file that still matches is counted as unverified in the summary and makes the command exit non-zero; this is a review signal, not an automatic malware verdict.

For installed core, plugins and themes, references are resolved in this order:

1. `/usr/local/share/src/third-party/<kind>`
2. `/usr/share/cache/wordpress-security-audit/<kind>`
3. Download from the official WordPress.org repository and save to the cache

Archives are looked up by name: `<slug>.<version>.zip` for plugins and themes (the same name used by WordPress.org, e.g. `elementor.4.3.5.zip`) and `wordpress-<version>.zip` for the core.

This means that vendored or manually supplied third-party archives take precedence, while a local cache is used for successful downloads to avoid repeating network requests. Broken or empty downloads are discarded instead of being cached, and only valid ZIP files that pass `unzip -t` are kept. This is especially useful for old, paid, or otherwise unavailable plugins/themes whose original ZIP cannot always be fetched from WordPress.org.

In the compose setup, the local `volumes/third-party` directory is mounted read-only at `/usr/local/share/src/third-party`, and the `volumes/cache` directory is mounted read-write at `/usr/share/cache/wordpress-security-audit` so the script can reuse validated archives across runs.

### Script 2: `wsa-sanitize-images.sh`

Purpose:
- Scan the WordPress tree for files flagged by the YARA rules
- Filter only real image files using `identify`
- Save each original image to quarantine before replacing it
- Re-encode matching images with ImageMagick, then check the sanitized result against YARA
- Add a sanitized image hash to the custom whitelist only if the result still matches YARA

How to use it:

```bash
docker run --rm \
  -v "$PWD/volumes/www:/var/www/html:rw" \
  -v "$PWD/volumes/quarantine:/var/www/quarantine:rw" \
  -v "$PWD/volumes/yara-rules:/usr/share/yara-rules:rw" \
  wordpress-security-audit \
  /usr/local/bin/wsa-sanitize-images.sh
```

Before replacing an image, the script saves its original under `volumes/quarantine`, preserving the path relative to the WordPress root. Images that no longer match YARA after sanitization are not added to the whitelist. For images that still match, the script adds their sanitized hashes to `99-custom.yar` and updates `last_updated` once if at least one new rule was added. The site, quarantine, and rule volumes must be writable.

> Warning: always work on a backup or an isolated copy of the site before applying sanitization to production files.

> Note: Sanitization re-encodes images and strips metadata. Review the resulting images for visual or format changes; this process is not a guarantee that an image is safe.

### Interactive YARA match review

To review each matched file and its matched strings and offsets, run the script interactively:

```bash
docker compose run --rm wsa /usr/local/bin/wsa-process-matches.sh
```

For each file, choose `c` to continue, `a` to add its hash to the custom whitelist, `m` to move it to quarantine, or `q` to quit. Whitelist and quarantine actions change files or rules, so only use them after validating the finding and work on an isolated copy of the site. The quarantine directory preserves each file's path relative to the WordPress root.

---

## TODO

* [ ] Search for installed malware:
  * [ ] Site code **In progress**
  * [ ] Data / Database
* [ ] Check for vulnerabilities in installed WordPress versions, plugins, and themes
