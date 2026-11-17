# Third-party Themes and Plugins

This document describes how to obtain third-party theme and plugin packages. It
currently documents Avada and ThemeREX as examples.

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

## ThemeREX

The ThemeREX Updater plugin (`trx_updater`) integrates ThemeREX theme and plugin
updates into WordPress. Its settings are under **Appearance > ThemeREX
Updater**; when configured with a theme purchase key, updates are offered from
**Dashboard > Updates**. Do not disclose or log the purchase key.

In the inspected version, the updater gets the active parent theme slug from
WordPress's `template` option (`elementra` on the sample site) and resolves the
purchase key in this order:

1. `trx_updater_theme_key` — entered on the ThemeREX Updater settings page.
2. If the theme's `trx_addons_theme_<template>_activated` option is `1`,
   `purchase_code_<template>`.
3. Otherwise, `<template>_theme_code_activation`.

These are per-site `get_option()` values in that site's prefixed options table
(usually `wp_options`), not network-wide multisite options. `template` is the
parent theme slug, so a child theme does not change the option suffix. The
separate `purchase_code_src_<template>` value is used as the market/source
identifier (`src`), not as the purchase key.

### Downloading ThemeREX theme and plugin packages

The following is an observed manual download flow for the ThemeREX updater
server, not a provider-documented guarantee. It downloads packages; it does not
install them. The inspected `trx_updater` 2.2.2 code uses
`http://upgrade.themerex.net/upgrade.php`. Its requests put the purchase key
in the URL over unencrypted HTTP, where it may be exposed to network observers
and URL logs. Prefer a secure HTTPS download from the authenticated provider
account if available. Use this legacy endpoint only in an isolated,
controlled environment and only after accepting the credential exposure risk;
do not print the key, enable shell tracing (`set -x`), or run it on a shared
host. Ask ThemeREX for a supported HTTPS endpoint before using this for
production updates.

The commands assume Bash and WP-CLI in the site's WordPress root, with
`curl`, `grep`, `sed`, and `unzip` available. Set the theme slug/name for the
site. The example uses Elementra; its `skin` parameter is empty. The updater
uses a skin only for certain themes (such as `topper-personal`). No version is
passed to the endpoint, so it does not provide a way to request an arbitrary
older version.

```bash
set -euo pipefail

TRX_THEME_SLUG='elementra'
TRX_THEME_NAME='Elementra'
TRX_DOWNLOAD_DIR="$PWD/themerex-downloads"

SITE_URL="$(wp option get home)"
SITE_DOMAIN="${SITE_URL#*://}"
TRX_UPDATER_THEME_KEY="$(wp option get 'trx_updater_theme_key')"
TRX_SRC_CODE="$(wp option get "purchase_code_src_$TRX_THEME_SLUG")"
TRX_THEME_SKIN=''
# Skin its only required by `topper-personal` theme
if [ "$TRX_THEME_SLUG" = 'topper-personal' ]; then
    TRX_STYLESHEET=`wp option get 'stylesheet'`
    TRX_THEME_SKIN=`wp option get "theme_skin_$TRX_STYLESHEET"`
fi

if [[ -z "$TRX_UPDATER_THEME_KEY" ]]; then
    printf '%s\n' 'ThemeREX purchase key is empty; refusing to continue.' >&2
    exit 1
fi

mkdir -p "$TRX_DOWNLOAD_DIR"

curl --fail --location --silent --show-error --get \
    'http://upgrade.themerex.net/upgrade.php' \
    --data-urlencode 'action=install_theme' \
    --data-urlencode "src=$TRX_SRC_CODE" \
    --data-urlencode "key=$TRX_UPDATER_THEME_KEY" \
    --data-urlencode "theme_slug=$TRX_THEME_SLUG" \
    --data-urlencode "theme_name=$TRX_THEME_NAME" \
    --data-urlencode "skin=$TRX_THEME_SKIN" \
    --data-urlencode "domain=$SITE_DOMAIN" \
    --data-urlencode "rnd=$RANDOM" \
    --output "$TRX_DOWNLOAD_DIR/$TRX_THEME_SLUG.zip"

while IFS= read -r plugin; do
    plugin_zip="$(basename "$plugin")"
    printf 'Downloading theme-supplied plugin package: %s\n' "$plugin"
    curl --fail --location --silent --show-error --get \
        'http://upgrade.themerex.net/upgrade.php' \
        --data-urlencode 'action=install_plugin' \
        --data-urlencode "src=$TRX_SRC_CODE" \
        --data-urlencode "key=$TRX_UPDATER_THEME_KEY" \
        --data-urlencode "theme_slug=$TRX_THEME_SLUG" \
        --data-urlencode "theme_name=$TRX_THEME_NAME" \
        --data-urlencode "plugin=$plugin" \
        --data-urlencode "domain=$SITE_DOMAIN" \
        --data-urlencode "rnd=$RANDOM" \
        --output "$TRX_DOWNLOAD_DIR/$plugin_zip"
done < <(
    grep -RhoE --include='*.php' \
        "get_plugin_source_path[[:space:]]*\\([[:space:]]*['\"]plugins/[^'\"]+\\.zip['\"]" \
        "wp-content/themes/$TRX_THEME_SLUG" |
        sed -E "s/.*['\"]plugins\\///; s/['\"].*//" |
        sort -u
)

find "$TRX_DOWNLOAD_DIR" -maxdepth 1 -type f -name '*.zip' -print
```

The plugin loop extracts package paths passed to
`elementra_get_plugin_source_path()` in the theme source. It does not mean
every plugin recommended by the theme is supplied by ThemeREX. For the
inspected Elementra theme, this includes packages such as `trx_addons`,
`trx_updater`, `trx-wcext`, and (when enabled/activated)
`sitepress-multilingual-cms`; Elementor is not downloaded by this mechanism.
The plugin request uses `plugin=<slug>/<slug>.zip` and does not send `skin`.

Before installing packages, confirm that each response is actually a ZIP:

```bash
for archive in "$TRX_DOWNLOAD_DIR"/*.zip; do
    unzip -tq "$archive"
done
```

Inspect the archive listing and internal version headers without executing PHP.
Compare the versions with the site's recorded versions; the endpoint's response
and filename alone do not prove a specific version. If the intended exact
version is unavailable, record that rather than substituting another release.

### Installing the downloaded packages

Only install on an isolated copy or staging site after a backup. Upload the
verified parent theme ZIP via **Appearance > Themes > Add New > Upload Theme**
and each plugin ZIP via **Plugins > Add New > Upload Plugin**. Preserve the
child theme (for example, `elementra-child`) and local customizations. If
WordPress does not offer to replace an installed plugin, use the site's
controlled deployment procedure with a backup; do not delete its directory
first. Re-check installed version headers and test the site before promoting
the update.

### Preparing ThemeREX reference archives for the whitelist

This workflow only catalogs packages; it does not install or activate them.
Use the downloads above (or archives obtained over HTTPS from the provider)
and save them under the repository's curated third-party volume, using the
installed slug and the version confirmed inside each archive:

```text
volumes/third-party/themerex/themes/elementra.<version>.zip
volumes/third-party/themerex/plugins/trx_addons.<version>.zip
volumes/third-party/themerex/plugins/trx_updater.<version>.zip
```

Only add packages that are available and relevant to the site. For example, if
`trx_updater` is not being cataloged, omit its archive. Confirm that each
archive passes `unzip -tq`, inspect its internal version header without running
its PHP, and compare the version with the site's recorded version before
labeling it as an exact reference. The packages downloaded above have generic
filenames; rename them using the verified versions when copying them into the
catalog. Calculate and retain local provenance hashes for the collected
packages:

```bash
ELEMENTRA_VERSION='<verified-version>'
TRX_ADDONS_VERSION='<verified-version>'
mkdir -p volumes/third-party/themerex/themes volumes/third-party/themerex/plugins
cp themerex-downloads/elementra.zip \
    "volumes/third-party/themerex/themes/elementra.$ELEMENTRA_VERSION.zip"
cp themerex-downloads/trx_addons.zip \
    "volumes/third-party/themerex/plugins/trx_addons.$TRX_ADDONS_VERSION.zip"

sha256sum "volumes/third-party/themerex/themes/elementra.$ELEMENTRA_VERSION.zip"
sha256sum "volumes/third-party/themerex/plugins/trx_addons.$TRX_ADDONS_VERSION.zip"
```

If cataloging `trx_updater`, calculate its hash in the same way. These local
hashes identify the archives collected; they are not provider verification.
