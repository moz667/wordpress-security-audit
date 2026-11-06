include "whitelists/wordpress.yar"
include "whitelists/plugins.yar"
include "whitelists/themes.yar"
include "whitelists/custom.yar"

private rule IsWhitelisted
{
    condition:
        IsWhitelistedWordpress or
        IsWhitelistedPlugins or
        IsWhitelistedThemes or
        IsWhitelistedCustom
}
