/* Copyright (C) NBS System - All Rights Reserved
   Licensed under GNU LGPL v3.0 – See the LICENSE notice for details
*/
/*
    Careful. Those rules are pretty heavy on computation
    since the sha1sum may be recomputed for every test.
    Please make sure that you're calling those rules after all the others.
*/

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
