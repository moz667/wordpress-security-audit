# Third-party Themes and Plugins

This document describes how to obtain third-party theme and plugin packages. It
currently documents Avada as an example.

Keep the two workflows below separate:

- **Updating a site** changes the site's installed theme and plugins.
- **Preparing whitelist references** downloads packages for inspection and
  cataloging; it does not install them.

For whitelist references, the package must match the version installed on the
site. A filename or a version used in a request is not proof of the package's
actual version. If the provider does not supply the required version, record
that the exact reference could not be obtained rather than substituting a
different version.

## Avada

<!-- TODO: Revisit the use of WP-CLI inside the site container. If the PHP code
is already compromised, find a way to perform this process without WP-CLI,
such as reading the database directly and manually replacing the theme and
plugins. -->

### Updating an Avada site

This procedure downloads and installs the latest Avada theme and premium
plugins available for the registered site. It modifies the installation.
Run it only in an appropriate site environment, preferably an isolated copy.

For this investigation, updating the test site is necessary because no
supported way has been found to request an arbitrary specific Avada theme or
plugin version. The available download flow appears to provide the current
theme release and the latest plugin versions associated with it. Updating the
site makes its installed versions match the packages that can currently be
obtained; it does not recover an older version that the provider does not make
available.

The commands below assume a Bash shell in the registered site's container, in
the WordPress root directory. Install `curl`, `jq`, and `unzip` if they are not
already available. Do not share or log the purchase code.

Read the site details and the currently installed Avada version:

```bash
wp option get 'fusion_registration_data' | grep purchase_code
# Example output contains the purchase code; keep it private.
wp option get 'siteurl'
# https://example.com
wp core version
# 7.1.3
grep -E "define\(.*AVADA_VERSION" wp-content/themes/Avada/functions.php
# define( 'AVADA_VERSION', '7.16.2' );
```

Set the values for this site. Start with the currently installed theme version;
update `AVADA_THEME_VERSION` after installing the theme if its version changes.

```bash
set -euo pipefail

AVADA_PURCHASE_CODE='<SECRET>'
AVADA_WEBSITE='https://example.com'
WORDPRESS_CORE_VERSION='7.1.3'
AVADA_THEME_VERSION='7.16.2'
```

Download and install the theme:

```bash
curl --fail --location --silent --show-error \
    "https://updates.theme-fusion.com/?avada_action=get_theme&ver=$AVADA_THEME_VERSION&code=$AVADA_PURCHASE_CODE" \
    -H "User-Agent: WordPress/$WORDPRESS_CORE_VERSION; $AVADA_WEBSITE" \
    -H "Referer: $AVADA_WEBSITE" \
    -o Avada.zip

unzip -tq Avada.zip
wp theme install --force Avada.zip
grep -E "define\(.*AVADA_VERSION" wp-content/themes/Avada/functions.php
```

If the installed theme version changed, set `AVADA_THEME_VERSION` to the
version shown above. Then download and install the premium plugins listed by
Avada for that theme version:

```bash
curl --fail --location --silent --show-error \
    "https://updates.theme-fusion.com/?avada_action=get_plugins&avada_version=$AVADA_THEME_VERSION" \
    -o plugins.json

jq -r '.[] | select(.premium == true) | [.name, .slug, .latest_version] | @tsv' plugins.json |
while IFS="$(printf '\t')" read -r plugin_name plugin_slug plugin_version; do
    printf " * Downloading plugin '%s': %s.%s.zip\n" \
        "$plugin_name" "$plugin_slug" "$plugin_version"

    curl --fail --location --silent --show-error --get \
        --data-urlencode 'avada_action=get_download' \
        --data-urlencode "item_name=$plugin_name" \
        --data-urlencode "ver=$AVADA_THEME_VERSION" \
        --data-urlencode "code=$AVADA_PURCHASE_CODE" \
        -H "User-Agent: WordPress/$WORDPRESS_CORE_VERSION; $AVADA_WEBSITE" \
        -H "Referer: $AVADA_WEBSITE" \
        -o "$plugin_slug.$plugin_version.zip" \
        'https://updates.theme-fusion.com/'

    unzip -tq "$plugin_slug.$plugin_version.zip"
    wp plugin install --force "$plugin_slug.$plugin_version.zip"
    rm "$plugin_slug.$plugin_version.zip"
done

rm plugins.json
```

This plugin list uses each plugin's `latest_version`; it does not establish
that the downloaded version matches a particular site's previously installed
version.

### Preparing reference archives for the whitelist

Download archives into the local third-party catalog without installing them.
For example, run the commands from the repository root and use the directories
mounted as `volumes/third-party/avada/themes/` and
`volumes/third-party/avada/plugins/`.

Set the values using the versions recorded from the site. `AVADA_THEME_VERSION`
is the target version to verify. The previous-version request below is an
observed workaround for obtaining the next Avada theme version; it is not a
documented version-selection interface, so verify the contents of the returned
archive before using it as a reference.

```bash
set -euo pipefail

WORDPRESS_CORE_VERSION='7.1.3'
AVADA_PURCHASE_CODE='<SECRET>'
AVADA_WEBSITE='https://example.com'
AVADA_THEME_VERSION='7.16.4'
PREVIOUS_AVADA_THEME_VERSION='7.16.3'

mkdir -p volumes/third-party/avada/themes volumes/third-party/avada/plugins
```

Download the theme:

```bash
curl --fail --location --silent --show-error \
    "https://updates.theme-fusion.com/?avada_action=get_theme&ver=$PREVIOUS_AVADA_THEME_VERSION&code=$AVADA_PURCHASE_CODE" \
    -H "User-Agent: WordPress/$WORDPRESS_CORE_VERSION; $AVADA_WEBSITE" \
    -H "Referer: $AVADA_WEBSITE" \
    -o "volumes/third-party/avada/themes/Avada.$AVADA_THEME_VERSION.zip"

unzip -tq "volumes/third-party/avada/themes/Avada.$AVADA_THEME_VERSION.zip"
```

Download the premium plugin packages listed for this theme version:

```bash
curl --fail --location --silent --show-error \
    "https://updates.theme-fusion.com/?avada_action=get_plugins&avada_version=$AVADA_THEME_VERSION" \
    -o plugins.json

jq -r '.[] | select(.premium == true) | [.name, .slug, .latest_version] | @tsv' plugins.json |
while IFS="$(printf '\t')" read -r plugin_name plugin_slug plugin_version; do
    printf " * Downloading plugin '%s': %s.%s.zip\n" \
        "$plugin_name" "$plugin_slug" "$plugin_version"

    curl --fail --location --silent --show-error --get \
        --data-urlencode 'avada_action=get_download' \
        --data-urlencode "item_name=$plugin_name" \
        --data-urlencode "ver=$AVADA_THEME_VERSION" \
        --data-urlencode "code=$AVADA_PURCHASE_CODE" \
        -H "User-Agent: WordPress/$WORDPRESS_CORE_VERSION; $AVADA_WEBSITE" \
        -H "Referer: $AVADA_WEBSITE" \
        -o "volumes/third-party/avada/plugins/$plugin_slug.$plugin_version.zip" \
        'https://updates.theme-fusion.com/'

    unzip -tq "volumes/third-party/avada/plugins/$plugin_slug.$plugin_version.zip"
done

rm plugins.json
```

The plugin endpoint returns `latest_version` values. These downloads are
therefore latest-version references, not necessarily the versions installed on
the site. Compare each archive's internal plugin `Version` header with the
installed version before treating it as an exact whitelist reference. If they
do not match, do not label the archive as the installed version.

Before adding any downloaded package to the curated catalog:

1. Confirm that `unzip -tq` succeeds.
2. Inspect the archive contents without executing its PHP code. Check the
   theme's `Version` in `style.css` or the plugin's `Version` in its main PHP
   file, and compare it with the version recorded from the site.
3. Keep the provider, retrieval date, target and observed package versions,
   and SHA-256 hash with the package provenance:

   ```bash
   sha256sum volumes/third-party/avada/themes/Avada.*.zip
   sha256sum volumes/third-party/avada/plugins/*.zip
   ```

4. If the provider only offers a different version, note that the exact
   reference is unavailable. Do not treat a newer or otherwise different
   package as equivalent.

### Package checksums and authenticity

Ideally, providers would publish a SHA-256 checksum for every package and
version, alongside an immutable record of the package name, version, and
filename. A checksum downloaded from the same server as the package can detect
accidental corruption or later changes, but it does not prove authenticity if
both files could have been replaced together. A digital signature verifiable
with a trusted provider public key offers stronger assurance.

No provider-published checksum or signature has been identified in the Avada
download flow documented here. The locally calculated SHA-256 is still useful
for identifying the exact archive collected and detecting changes to it later,
but it is not proof that the archive is authentic or matches a provider's
release. Record it as a local provenance hash, not as provider verification.
