package io.passauth.app

import io.passauth.app.data.OtpAuth
import io.passauth.app.data.OtpKey
import io.passauth.app.data.OtpParse
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class OtpAuthTest {
    private fun valid(s: String): OtpKey = (OtpAuth.parse(s) as? OtpParse.Valid)?.key ?: error("expected valid: $s -> ${OtpAuth.parse(s)}")
    private fun invalid(s: String) = assertTrue("expected invalid: $s", OtpAuth.parse(s) is OtpParse.Invalid)

    @Test
    fun otpauthUriIsStoredWhole() {
        val uri = "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=SHA1&digits=6&period=30"
        val k = valid(uri)
        assertEquals(uri, k.value)
        assertEquals("Example", k.issuer)
        assertEquals("alice@example.com", k.account)
        assertEquals("Example (alice@example.com)", k.label)
    }

    @Test
    fun uriLabelIsDecodedAndIssuerFallsBackToPrefix() {
        val k = valid("otpauth://totp/ACME%20Co:john.doe%40email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ")
        assertEquals("ACME Co", k.issuer)
        assertEquals("john.doe@email.com", k.account)
    }

    @Test
    fun uppercaseSchemeIsNormalisedForTheCore() {
        // QR codes in alphanumeric mode are often all upper case; the core expects "otpauth://totp/".
        val k = valid("OTPAUTH://TOTP/EX:BOB?SECRET=JBSWY3DPEHPK3PXP&ISSUER=EX")
        assertTrue(k.value.startsWith("otpauth://totp/EX:BOB?"))
    }

    @Test
    fun uriParametersAreChecked() {
        valid("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=sha256&digits=8&period=60")
        invalid("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=MD5")
        invalid("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=5")
        invalid("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=11")
        invalid("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&period=0")
        invalid("otpauth://totp/x?issuer=Nope")
        invalid("otpauth://totp/x?secret=not*base32")
    }

    @Test
    fun unsupportedKinds() {
        invalid("otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP&counter=1")
        invalid("otpauth-migration://offline?data=CjEKCkhlbGxvId6tvu8")
        invalid("https://example.com/2fa")
        invalid("")
        invalid("   ")
    }

    @Test
    fun plainBase32IsCleaned() {
        assertEquals("JBSWY3DPEHPK3PXP", valid("jbsw y3dp ehpk 3pxp").value)
        assertEquals("JBSWY3DPEHPK3PXP", valid("JBSW-Y3DP-EHPK-3PXP").value)
        assertEquals("GEZDGNBV", valid("GEZDGNBV").value)
        assertEquals("", valid("GEZDGNBV").label)
    }

    @Test
    fun plainBase32Errors() {
        invalid("JBSWY3DPEHPK3PX1") // 1 isn't base32
        invalid("A") // impossible length
        invalid("MZ") // non-zero trailing bits (non-canonical), rejected by the core too
    }

    @Test
    fun base32Decoding() {
        assertArrayEquals("Hello!".toByteArray() + byteArrayOf(0xDE.toByte(), 0xAD.toByte(), 0xBE.toByte(), 0xEF.toByte()), OtpAuth.decodeBase32("JBSWY3DPEHPK3PXP"))
        assertArrayEquals("12345".toByteArray(), OtpAuth.decodeBase32("GEZDGNBV"))
        assertArrayEquals("f".toByteArray(), OtpAuth.decodeBase32("MY"))
        assertNull(OtpAuth.decodeBase32(""))
    }

    @Test
    fun usableValues() {
        assertTrue(OtpAuth.isUsable(null))
        assertTrue(OtpAuth.isUsable(""))
        assertTrue(OtpAuth.isUsable("JBSWY3DPEHPK3PXP"))
        assertTrue(!OtpAuth.isUsable("hello world"))
    }
}
