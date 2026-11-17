import "hash"

private rule IsWhitelistedOficialRepository: Whitelist WLOficialRepository
{
    meta:
        last_updated = "2026-11-06T05:56:00.000000"

    condition:
        // [START] wordpress core 7.1.4 (source: WordPress.org)
        hash.sha256(0, filesize) == "98ce3cfb581e3aa48bfd94a5ecf7686d6f45d39fd9dd9d216cbc69d87825bd23" or // wordpress/wp-admin/includes/class-ftp.php
        hash.sha256(0, filesize) == "39f881d3c1957fc97111886079db76f1b0798b72d991d90682a4de1f17b270e1" or // wordpress/wp-admin/includes/class-pclzip.php
        hash.sha256(0, filesize) == "b5c9e9c679d0719277ed83f99c8eacccabcc3f5459857027cf361f6e63a328a4" or // wordpress/wp-admin/includes/class-wp-automatic-updater.php
        hash.sha256(0, filesize) == "8a0dd30bb92883fc7c224b453f26b83c07fb867668d608f31097abbbd3155073" or // wordpress/wp-admin/includes/class-wp-debug-data.php
        hash.sha256(0, filesize) == "231856cc5f7bc8d06996a3357c94afb2b270075a93b4211f5a66c4869e36c8ac" or // wordpress/wp-admin/includes/file.php
        hash.sha256(0, filesize) == "61a45a0d8551fd8323f28fc3d4b630857e00bea80a69c93f31a34bb76ec3c24a" or // wordpress/wp-admin/includes/media.php
        hash.sha256(0, filesize) == "5ed2dc97277dd3a9be0caac0b6ac47509473b520579144265a623cfca4392a4b" or // wordpress/wp-admin/includes/template.php
        hash.sha256(0, filesize) == "cfb84ed7624486c527ab8126dbc1503a7a448fd8577f8b13fb6ecf769fda6c9f" or // wordpress/wp-includes/ID3/getid3.php
        hash.sha256(0, filesize) == "d90f2d9db3938373228febc1d96b1292d0fe8bc0da5c75afdf01c08a2ec0d0b1" or // wordpress/wp-includes/ID3/module.audio-video.matroska.php
        hash.sha256(0, filesize) == "1795add5fe254d5c158af0b1d7914bc7bb8b2267049ef2fb7a2edd139e3540fe" or // wordpress/wp-includes/ID3/module.audio-video.quicktime.php
        hash.sha256(0, filesize) == "951c3efaacbcab2137cdb0078461e695fa7f5378d2f69ca9aac34a9a3426a659" or // wordpress/wp-includes/ID3/module.tag.id3v2.php
        hash.sha256(0, filesize) == "b2e1772879cf36db6f539d6186c035936d0031afb87f8f3c4c216d16ed13a4d5" or // wordpress/wp-includes/IXR/class-IXR-date.php
        hash.sha256(0, filesize) == "522bcf0d07be7e7e00114711db5c9ce2b4d59ac041c5ec36eaadd979d5fa7046" or // wordpress/wp-includes/PHPMailer/SMTP.php
        hash.sha256(0, filesize) == "7c4fc2bc550b36d1d7869ae4dc27197cef50557fadb4ae23e4afdf87c7300e33" or // wordpress/wp-includes/SimplePie/src/File.php
        hash.sha256(0, filesize) == "8269eea9c2eeb5b949109a1342af1217aa263eab489359b134c8ab80e32dddfc" or // wordpress/wp-includes/SimplePie/src/Item.php
        hash.sha256(0, filesize) == "d0d6e4e006d140b3e0dc97124c8d89f24e4433d3d0edac910d7b3c124018f3df" or // wordpress/wp-includes/SimplePie/src/Misc.php
        hash.sha256(0, filesize) == "8a995ca13d2f1d476f60cba0aea6ab2d04b2e205d297e472740d80c9f366d128" or // wordpress/wp-includes/SimplePie/src/Parse/Date.php
        hash.sha256(0, filesize) == "0f8d2f4d5b24674340cf6256c3ca2421c02701d87e4c61b6ccc2c607dcd78b8c" or // wordpress/wp-includes/SimplePie/src/Sanitize.php
        hash.sha256(0, filesize) == "14adaf4bd50fa87f3b7af39f022eb52b1fa82a25b4f6ede99af9083a60408e96" or // wordpress/wp-includes/SimplePie/src/SimplePie.php
        hash.sha256(0, filesize) == "12c5bca1c152be6440fae3f0c949fb7d335fab66a4d162e62f10fad5f79924ba" or // wordpress/wp-includes/block-supports/elements.php
        hash.sha256(0, filesize) == "4c0cf2784ad07bb4004ba3660ad44919c5c20f72700b91d480774a3ad3dd9d3f" or // wordpress/wp-includes/block-supports/layout.php
        hash.sha256(0, filesize) == "8d8087c1dc1ffa02de3ac031289b8292ebb94182c4a5efc00ac99f869892d0ad" or // wordpress/wp-includes/blocks/rss.php
        hash.sha256(0, filesize) == "7fe0dd67f50a833989d143759d1f98deb92f51df9aec69ea57bbe6e3290b689a" or // wordpress/wp-includes/bookmark-template.php
        hash.sha256(0, filesize) == "48f529825e0e18fa09e5e5da90628a163874a6e65e67ecbbe8e535c840c6870a" or // wordpress/wp-includes/class-wp-block-processor.php
        hash.sha256(0, filesize) == "903d70e399388560d76ebe68264df839922ebabd7e05c7a32345c5c53f7312a4" or // wordpress/wp-includes/class-wp-date-query.php
        hash.sha256(0, filesize) == "22763447b928ceacc9a3f0cb835c9dc094b168ba1f8f8088319bd0381c8dce70" or // wordpress/wp-includes/class-wp-meta-query.php
        hash.sha256(0, filesize) == "22eb4845078ec33afd9e5123c88817002542ce38f14ade73cf0a498ad5236c39" or // wordpress/wp-includes/class-wp-tax-query.php
        hash.sha256(0, filesize) == "a0096570cb00b2f04b362b6a9af46851bd48a80f332392dfcf004de077205159" or // wordpress/wp-includes/deprecated.php
        hash.sha256(0, filesize) == "c9b6c2b3c24c788db11718c1008819e0a1d62c6ba45b6a1b1b9a832cd3981b9d" or // wordpress/wp-includes/embed.php
        hash.sha256(0, filesize) == "cac8a17e293df99f0683a88debd3ba5e5cce274183a4e9fd3c9f18375747f41c" or // wordpress/wp-includes/functions.php
        hash.sha256(0, filesize) == "1ece39fcc40380d7c5faa047577be0944a9308d75ac46355b1d1844790341ffe" or // wordpress/wp-includes/html-api/class-wp-html-decoder.php
        hash.sha256(0, filesize) == "3560ff58ef987a313be5b591fa4c8f61899585df9728661e072b1b39d8555a6a" or // wordpress/wp-includes/kses.php
        hash.sha256(0, filesize) == "5396f89cd77916722631fe98ccd1591a861460011fa2f7a535b071f7b7ffdfb7" or // wordpress/wp-includes/nav-menu-template.php
        hash.sha256(0, filesize) == "9cb15c0f7fc9bb52bd6d0211e544f84dd3b05e150b2a046c7cbdb3350e1eec70" or // wordpress/wp-includes/post-template.php
        hash.sha256(0, filesize) == "9c4af1341e37de253323cf7c28da1424f41decc2154904e2b71a4e71c9cdd70c" or // wordpress/wp-includes/rest-api.php
        // [END] wordpress core 7.1.4 (source: WordPress.org)

		// End rule
        false
}
