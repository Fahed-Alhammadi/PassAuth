package io.passauth.app.data

/**
 * Public suffixes: one list for autofill site matching ([UrlMatcher]) and passkey
 * RP ID checks (`credentials/WebAuthn`). The same list is in the extension
 * (`background/psl.ts`) and the iOS app (`Shared/PublicSuffixes.swift`); keep them in sync.
 *
 * Small built-in list of multi-label public suffixes (ICANN + common private
 * hosting and dynamic-DNS suffixes). LIMITATION: this is not the full Public
 * Suffix List, so a host under an unlisted multi-label suffix falls back to its
 * last two labels. Single-label suffixes ("com", "app", ...) are handled by callers.
 */
object PublicSuffixes {
    val MULTI_LABEL: Set<String> = setOf(
        // United Kingdom
        "co.uk", "org.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk", "sch.uk", "ac.uk", "gov.uk", "nhs.uk", "police.uk",
        // Australia / New Zealand
        "com.au", "net.au", "org.au", "edu.au", "gov.au", "asn.au", "id.au",
        "co.nz", "net.nz", "org.nz", "ac.nz", "govt.nz", "geek.nz", "school.nz",
        // Asia
        "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp", "gr.jp", "ad.jp", "ed.jp", "lg.jp",
        "co.kr", "ne.kr", "or.kr", "re.kr", "go.kr", "ac.kr",
        "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "ac.cn",
        "com.hk", "net.hk", "org.hk", "edu.hk", "gov.hk", "idv.hk",
        "com.tw", "net.tw", "org.tw", "edu.tw", "gov.tw", "idv.tw",
        "com.sg", "net.sg", "org.sg", "edu.sg", "gov.sg", "per.sg",
        "com.my", "net.my", "org.my", "edu.my", "gov.my",
        "co.in", "net.in", "org.in", "firm.in", "gen.in", "ind.in", "ac.in", "edu.in", "gov.in", "res.in",
        "co.id", "or.id", "ac.id", "go.id", "web.id", "my.id",
        "com.ph", "net.ph", "org.ph", "gov.ph",
        "com.vn", "net.vn", "org.vn", "edu.vn", "gov.vn",
        "co.th", "in.th", "ac.th", "go.th", "or.th",
        "com.pk", "net.pk", "org.pk", "edu.pk", "gov.pk",
        "com.bd", "com.np", "com.lk",
        // Middle East / Africa
        "com.sa", "net.sa", "org.sa", "edu.sa", "gov.sa", "med.sa",
        "co.ae", "net.ae", "org.ae", "gov.ae", "ac.ae", "sch.ae",
        "com.qa", "com.kw", "com.bh", "com.om", "com.jo", "com.lb",
        "co.il", "org.il", "net.il", "ac.il", "gov.il", "muni.il",
        "com.tr", "net.tr", "org.tr", "edu.tr", "gov.tr", "gen.tr",
        "com.eg", "net.eg", "org.eg", "edu.eg", "gov.eg",
        "co.za", "org.za", "net.za", "web.za", "gov.za", "ac.za",
        "com.ng", "org.ng", "gov.ng", "co.ke", "or.ke", "ac.ke", "co.tz", "co.ug", "com.gh", "co.ma",
        // Americas
        "com.br", "net.br", "org.br", "gov.br", "edu.br", "art.br", "blog.br",
        "com.mx", "net.mx", "org.mx", "gob.mx", "edu.mx",
        "com.ar", "net.ar", "org.ar", "gob.ar", "edu.ar",
        "com.co", "net.co", "org.co", "gov.co", "edu.co",
        "com.pe", "net.pe", "org.pe", "gob.pe", "com.ve", "co.ve", "com.ec", "com.uy", "com.py", "com.bo",
        "cl.cl", "gob.cl", "co.cr", "com.gt", "com.do", "com.pr",
        // Europe
        "co.at", "or.at", "ac.at", "gv.at", "com.pl", "net.pl", "org.pl", "gov.pl", "edu.pl",
        "com.ua", "net.ua", "org.ua", "gov.ua", "com.ru", "net.ru", "org.ru", "com.gr", "com.cy", "com.mt",
        "com.pt", "com.es", "nom.es", "org.es", "com.ro", "co.hu", "com.hr", "co.rs", "com.ee", "co.no",
        // Common private hosting suffixes
        "github.io", "gitlab.io", "herokuapp.com", "appspot.com", "blogspot.com", "cloudfront.net",
        "netlify.app", "vercel.app", "pages.dev", "workers.dev", "web.app", "firebaseapp.com",
        "azurewebsites.net", "azurestaticapps.net", "s3.amazonaws.com", "elasticbeanstalk.com",
        "onrender.com", "fly.dev", "glitch.me", "repl.co", "ngrok.io", "ngrok.app", "ngrok-free.app",
        "trycloudflare.com", "duckdns.org", "dyndns.org", "no-ip.org", "eu.org", "readthedocs.io",
        // Dynamic DNS and hosting suffixes common for self-hosted servers (anyone can register a name under these)
        "ddns.net", "hopto.org", "zapto.org", "sytes.net", "no-ip.biz", "no-ip.info", "freeddns.org", "dynu.net",
        "synology.me", "myqnapcloud.com", "ts.net", "myshopify.com", "amplifyapp.com", "deno.dev", "up.railway.app",
        "surge.sh", "loca.lt", "serveo.net", "localto.net",
    )

    /** The longest listed public suffix [host] ends with ("" if none). */
    fun suffixOf(host: String): String {
        val labels = host.split('.')
        for (i in 1 until labels.size) {
            val s = labels.subList(i, labels.size).joinToString(".")
            if (s in MULTI_LABEL) return s
        }
        return ""
    }
}
