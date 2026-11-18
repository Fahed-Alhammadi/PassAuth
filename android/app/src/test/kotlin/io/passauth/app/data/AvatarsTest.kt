package io.passauth.app.data

import io.passauth.app.ui.components.SiteTileContent
import io.passauth.app.ui.components.siteTileContent
import java.nio.file.Files
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Profile pictures (Avatars.kt): encode limits, when to fetch, the per-account cache; the site tile rule. */
class AvatarsTest {
    private fun cache(dir: java.io.File) = AvatarCache(
        dir,
        // A stand-in for the Keystore seal: reversible, and not the plain bytes.
        seal = { b -> b.reversedArray() },
        open = { b -> b.reversedArray() },
    )

    @Test
    fun centreSquareCropsTheLongSide() {
        assertEquals(Triple(100, 0, 300), AvatarRules.centerSquare(500, 300))
        assertEquals(Triple(0, 50, 200), AvatarRules.centerSquare(200, 300))
        assertEquals(Triple(0, 0, 256), AvatarRules.centerSquare(256, 256))
    }

    @Test
    fun encodeLowersQualityUntilItFits() {
        val tried = mutableListOf<Int>()
        // Bigger than the limit at high quality, within it from quality 55 on.
        val out = AvatarRules.encodeWithin { q -> tried += q; ByteArray(if (q > 55) AvatarRules.MAX_BYTES + 1 else 100_000) }
        assertNotNull(out)
        assertTrue(out!!.size <= AvatarRules.MAX_BYTES)
        assertEquals(listOf(85, 75, 65, 55), tried)
        assertNull(AvatarRules.encodeWithin { ByteArray(AvatarRules.MAX_BYTES + 1) })
        assertNull(AvatarRules.encodeWithin { ByteArray(0) })
        assertEquals(256 * 1024, AvatarRules.MAX_BYTES)
    }

    @Test
    fun fetchesOnlyWhenTheSequenceChanges() {
        assertFalse(AvatarRules.needsFetch(0, 0)) // never set
        assertFalse(AvatarRules.needsFetch(3, 3)) // kept already
        assertFalse(AvatarRules.needsFetch(3, null)) // an older server: no pictures
        assertTrue(AvatarRules.needsFetch(0, 1)) // set elsewhere
        assertTrue(AvatarRules.needsFetch(3, 4)) // changed or removed elsewhere
    }

    @Test
    fun cacheKeepsSequenceAndPictureAndIsDeletedOnLogout() {
        val dir = Files.createTempDirectory("avatars").toFile()
        try {
            val c = cache(dir)
            assertNull(c.read("a"))
            val jpeg = byteArrayOf(-1, -40, 1, 2, 3)
            c.write("a", 7, jpeg)
            c.write("b", 2, ByteArray(0)) // removed: "none at seq 2"
            val a = c.read("a")!!
            assertEquals(7, a.seq)
            assertArrayEquals(jpeg, a.jpeg)
            assertTrue(a.hasPicture)
            assertFalse(c.read("b")!!.hasPicture)
            assertEquals(2, c.read("b")!!.seq)
            // Sealed on disk, never the plain JPEG.
            assertFalse(dir.resolve("a.bin").readBytes().copyOfRange(0, 8).contentEquals(java.nio.ByteBuffer.allocate(8).putLong(7).array()))
            // Log out: gone, so the next sign-in fetches it again (seq 0).
            c.delete("a")
            assertNull(c.read("a"))
            // Records gone from the device: their files go too.
            c.write("a", 1, jpeg)
            c.prune(setOf("a"))
            assertNotNull(c.read("a"))
            assertNull(c.read("b"))
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun unreadableCacheCountsAsNone() {
        val dir = Files.createTempDirectory("avatars").toFile()
        try {
            dir.resolve("x.bin").writeBytes(byteArrayOf(1, 2))
            assertNull(cache(dir).read("x"))
            val failing = AvatarCache(dir, { it }, { throw java.security.GeneralSecurityException("bad tag") })
            dir.resolve("y.bin").writeBytes(ByteArray(20))
            assertNull(failing.read("y"))
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun siteTileShowsAGlobeForLoginsWhenIconsAreOff() {
        assertEquals(SiteTileContent.Globe, siteTileContent(enabled = false, hasIcon = false, login = true))
        assertEquals(SiteTileContent.Globe, siteTileContent(enabled = false, hasIcon = true, login = true))
        // Other kinds keep their letter; icons on but missing or failed: the letter.
        assertEquals(SiteTileContent.Letter, siteTileContent(enabled = false, hasIcon = false, login = false))
        assertEquals(SiteTileContent.Letter, siteTileContent(enabled = true, hasIcon = false, login = true))
        assertEquals(SiteTileContent.Icon, siteTileContent(enabled = true, hasIcon = true, login = true))
    }

    /** Review L8: a very wide or tall picked image is never decoded at full size. */
    @Test
    fun aPickedImageIsDecodedBoundedOnBothSides() {
        // Small enough already.
        assertNull(AvatarRules.decodeSize(512, 512))
        assertNull(AvatarRules.decodeSize(4096, 500))
        // A photo: the short side comes down to twice the picture's side.
        assertEquals(682 to 512, AvatarRules.decodeSize(8000, 6000))
        // A strip 100,000 wide and 500 high (its short side alone would let it through at full size): capped by the long side.
        val strip = AvatarRules.decodeSize(100_000, 500)!!
        assertTrue("$strip", strip.first in 4095..AvatarRules.MAX_DECODE_SIDE && strip.second in 1..500)
        val tall = AvatarRules.decodeSize(300, 2_000_000)!!
        assertTrue("$tall", tall.first == 1 && tall.second in 4095..AvatarRules.MAX_DECODE_SIDE)
        // Never more than 4096 × 4096 pixels (64 MB as ARGB), whatever the image says.
        for ((w, h) in listOf(Int.MAX_VALUE to Int.MAX_VALUE, Int.MAX_VALUE to 1, 5000 to 5000, 4097 to 4097)) {
            val size = AvatarRules.decodeSize(w, h)!!
            assertTrue("$w×$h → $size", size.first in 1..AvatarRules.MAX_DECODE_SIDE && size.second in 1..AvatarRules.MAX_DECODE_SIDE)
        }
        assertNull(AvatarRules.decodeSize(0, 10))
    }
}
