include "whitelists/10-oficial-repository.yar"
include "whitelists/20-third-party.yar"
include "whitelists/99-custom.yar"

private rule IsWhitelisted
{
    condition:
        IsWhitelistedOficialRepository or
        IsWhitelistedThirdParty or
        IsWhitelistedCustom
}
