# Plan: technical workflow for the WordPress Security Audit project

## Objective

Organize the project into a clear, technical, and executable workflow for detecting malware and suspicious changes in WordPress installations using a conservative, evidence-based strategy.

The project aims to:

- use YARA as the initial screening tool
- reduce false positives with a whitelist
- validate official and third-party packages
- isolate suspicious files in quarantine
- use wp-cli only as a supplementary aid, not as a definitive criterion

---

## Workflow principles

1. YARA is a triage tool, not a final verdict.
2. A YARA match does not prove that a file is malware.
3. The whitelist must be based on verifiable evidence.
4. Quarantine is used to isolate suspicious files before taking action.
5. Analysis must be performed on an isolated copy of the site.
6. wp-cli can help verify integrity, but it must not be the sole source of truth for a compromised installation.

---

## Workflow phases

### Phase 0: snapshot and isolation

Before scanning or modifying anything, work on an isolated copy of the site or a filesystem snapshot.

Why:
- avoids modifying the site's actual state
- avoids running suspicious site code during validation
- allows results to be evaluated safely

Decision:
- do not work on the live installation if compromise is suspected

---

### Phase 1: initial YARA scan

Run YARA against the entire WordPress tree.

Base command:

```bash
docker compose run --rm -T wsa
```

Objective:
- identify genuine candidates
- reduce the set of files to review
- detect suspicious code patterns, shell code, obfuscation, or payloads

Important:
- a match is an indicator, not confirmation of infection

---

### Phase 2: generate a whitelist for known-good files

The main script is:

- `scripts/wsa-auto-add-to-whitelists.sh`

What it does:
- scans the site and records files that trigger YARA
- processes every ZIP in the curated third-party volume, including packages not installed in the site
- resolves official core, plugin, and theme reference packages for installed files that trigger YARA
- generates hashes for matching files in those trusted packages
- persists each validated rule block as it is generated
- supports `--dry-run` to preview without changing whitelist files
- validates the candidate rules and rescans the files found in the initial site scan

Default command (generates and persists rules incrementally):

```bash
docker compose run --rm -T wsa /usr/local/bin/wsa-auto-add-to-whitelists.sh
```

Preview command:

```bash
docker compose run --rm -T wsa /usr/local/bin/wsa-auto-add-to-whitelists.sh --dry-run
```

Whitelist rules are now organized by source and confidence:

- `yara-rules/whitelists/10-oficial-repository.yar` — files verified against the official WordPress repository
- `yara-rules/whitelists/20-third-party.yar` — packages from the curated third-party volume, including plugins and themes
- `yara-rules/whitelists/99-custom.yar` — manually validated exceptions, including custom rules for image false positives

The cache is reserved for archives downloaded by the script from WordPress.org, so cached packages are added to the official-repository whitelist. Archives under `./volumes/third-party` are added to the third-party whitelist. Each validated block is saved immediately, so failures in later packages do not discard earlier rules. At the end of a run, `last_updated` is refreshed once in each generated whitelist that received new rules. In `--dry-run`, the script makes no whitelist or timestamp changes and reports the number of rules that would be added.

The script reports progress and a concise final summary rather than printing individual hashes or successful verification lines. The summary includes the number of rules added, files that remain unverified, and errors. After the summary, unavailable reference resources are listed with their type, slug/version, and download URL. Remaining matches require investigation and are not automatically classified as malware.

Source resolution:

1. `./volumes/third-party`
2. local cache
3. official download from WordPress.org

This prevents legitimate plugin and theme files from being flagged as suspicious due to a generic pattern.

---

### Phase 3: whitelist official and third-party packages

Use the source-based rule groups:

- `10-oficial-repository.yar` for files verified against the official WordPress repository, including core, plugins, themes, or language packages
- `20-third-party.yar` for packages supplied in the curated `./volumes/third-party` catalog, including purchased or older plugins and themes
- `99-custom.yar` for manually reviewed exceptions that do not belong in a package-based whitelist

Key decision:
- if the source is unknown, do not automatically accept it as clean

---

### Phase 4: quarantine suspicious and modifiable files

This covers items that may have been altered by injection or by the site's own operation.

Examples:
- suspicious images
- `.mo` and `.po` files that do not match the original package
- unexpected content changes in a plugin or theme
- unusual files outside the expected root directory
- files added to execution paths or automatically loaded locations

Helper script:
- `scripts/sanitize-yara-matched-images.sh`

Exact command:

```bash
docker run --rm \
  -v "$PWD/volumes/www:/var/www/html:rw" \
  -v "$PWD/volumes/yara-rules:/usr/share/yara-rules:ro" \
  wordpress-security-audit \
  /usr/local/bin/sanitize-yara-matched-images.sh
```

What it does:
- locates images flagged by YARA
- filters for actual image files only
- rewrites the image to break the malicious structure
- generates hashes for the whitelist

Important:
- this operation modifies actual files
- it must only be performed on an isolated copy

---

### Phase 5: integrity validation and comparison against a reference

Validation checks whether an actual file has been altered from its source.

Two types of validation are used:

1. hash comparison
2. comparison against the original package, cache, or download

Helper commands:

```bash
docker compose run --rm --entrypoint sh wsa -lc "wp --allow-root core verify-checksums"
```

It can also be used to list plugins and versions:

```bash
docker compose run --rm --entrypoint sh wsa -lc "wp --allow-root plugin list --field=name,version"
```

However:
- wp-cli should only be used as a supplementary aid
- if the site can execute code from WordPress itself or from plugins, that environment is not safe for direct diagnosis
- a compromised site may deceive validation checks or run more code than expected

Therefore, the recommendation is:
- use wp-cli in a clean environment or on the isolated copy
- do not rely on wp-cli as the only evidence

---

### Phase 6: rescan with YARA after cleanup

Once false positives have been reduced and suspicious files isolated, run another scan:

```bash
docker compose run --rm -T wsa yara -r /usr/share/yara-rules/php.yar /var/www/html
```

Objective:
- confirm whether any genuine cases remain
- distinguish noise from persistent threats
- check whether the injection is still present after validation

---

### Phase 7: final classification of findings

Each case should ultimately be classified as:

- false positive
- modified official package
- altered plugin/theme
- unexpected extra file
- actual payload
- shell or webshell
- code hidden in an image
- execution risk in mu-plugins or automatically loaded paths

Next decision:
- restore from a clean source
- replace the file with a valid version
- move it to quarantine
- review it manually
- add it to the whitelist if validated as legitimate

---

## Script by script

### 1) `wsa-auto-add-to-whitelists.sh`

Path:
- `scripts/wsa-auto-add-to-whitelists.sh`

Objective:
- reduce noise using hashes from official packages
- determine whether suspicious files belong to the standard core, plugins, or themes

What it does exactly:
- traverses `/var/www/html`
- detects the WordPress version
- finds plugins and themes with YARA matches
- resolves the original package in this order:
  1. local third-party packages
  2. local cache
  3. official download
- extracts the zip file
- generates hashes for those files
- prints YARA rules ready to copy

Run:

```bash
docker compose run --rm -T wsa /usr/local/bin/wsa-auto-add-to-whitelists.sh > /tmp/whitelist-output.txt
```

Important rule:
- do not trust a file solely because it “looks official”

---

### 2) `sanitize-yara-matched-images.sh`

Path:
- `scripts/sanitize-yara-matched-images.sh`

Objective:
- clean suspicious images containing detected payloads or strings
- break the malicious structure without destroying the visual appearance

What it does exactly:
- runs YARA against the tree
- selects only files that are actual images
- rewrites the image in place to break the injection
- generates the resulting hashes for the whitelist

Run:

```bash
docker run --rm \
  -v "$PWD/volumes/www:/var/www/html:rw" \
  -v "$PWD/volumes/yara-rules:/usr/share/yara-rules:ro" \
  wordpress-security-audit \
  /usr/local/bin/sanitize-yara-matched-images.sh
```

Warning:
- modifies actual files
- must only be run on a copy or snapshot

---

### 3) `wsa-add-file-to-whitelist.sh`

Path:
- `scripts/wsa-add-file-to-whitelist.sh`

Objective:
- add the hash of a legitimate file to the custom whitelist

What it does exactly:
- calculates the file's SHA256
- inserts it into `99-custom.yar`
- prevents duplicates
- refreshes `last_updated` when a new hash is added
- helps mark false positives or files that have already been validated

Run:

```bash
docker compose run --rm -T wsa /usr/local/bin/wsa-add-file-to-whitelist.sh /var/www/html/wp-content/plugins/example/example.php
```

Or multiple files together:

```bash
docker compose run --rm -T wsa /usr/local/bin/wsa-add-file-to-whitelist.sh \
  /var/www/html/wp-content/plugins/example/example.php \
  /var/www/html/wp-content/themes/demo/style.css
```

Recommended uses:
- a file already validated manually
- a recognized official package
- a false positive that has already been reviewed

---

## Project and relevant paths

- `docker-compose.yml` → mounts `www`, YARA rules, and third-party packages
- `Dockerfile` → contains the image with YARA, scripts, and rules
- `yara-rules/php.yar` → primary detection rule
- `yara-rules/whitelist.yar` → central whitelist logic
- `yara-rules/whitelists/10-oficial-repository.yar` → hashes verified against the official repository
- `yara-rules/whitelists/20-third-party.yar` → hashes verified against third-party reference packages
- `yara-rules/whitelists/99-custom.yar` → manually validated exceptions
- `volumes/third-party` → local plugin/theme/language packages
- `volumes/cache` → cache of validated downloads
- `volumes/www` → WordPress site to audit

---

## Final recommendation for the project workflow

The recommended sequence is:

```text
snapshot/isolated copy
  -> baseline YARA scan
  -> wsa-auto-add-to-whitelists.sh
  -> official + third-party whitelist
  -> quarantine suspicious files
  -> integrity validation
  -> sanitize-yara-matched-images.sh if applicable
  -> final verification YARA scan
  -> decision: restore / isolate / whitelist / review manually
```

The key to the project is not “detecting malware at any cost,” but rather:
- reducing noise
- working with evidence
- avoiding hasty decisions
- distinguishing legitimate software from altered content

---

## Conclusion

This workflow makes it clear that the project should operate as a validation chain:

- YARA to detect candidates
- hash whitelist to separate “normal” files
- third-party packages/cache to provide context for each package
- quarantine to protect evidence
- additional validation to confirm integrity
- a final rescan to determine whether there is a real threat

This is the best way to organize the project without relying on low-confidence detections or jumping to conclusions.
