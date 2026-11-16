package io.passauth.app.data

import io.passauth.core.ApprovedLoginInterface
import io.passauth.core.CoreException
import io.passauth.core.LoginApproval
import io.passauth.core.loginPhraseChoices
import java.security.SecureRandom
import java.util.Base64
import java.util.Locale
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.delay
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.longOrNull
import kotlinx.serialization.json.put

/*
 * Sign in with another device's approval (servers with the `login_with_device` feature; server
 * side crates/server/src/auth_requests.rs, keys in crates/core/src/device_login.rs). The pure
 * parts, unit-tested in DeviceLoginTest: the new device's request, its wait for an answer
 * ([DeviceLoginFlow] over a [DeviceLoginTransport]) and the code that confirms an approval
 * ([DeviceLogin.check]); the approving app's list, its frozen one-at-a-time queue and its answer
 * ([DeviceApprovals], [ApprovalQueue]). VaultRepository supplies the real transport and keys;
 * AuthRequestInbox and the sign-in screen use them.
 *
 * An approval is only usable on the new device after the user typed the 6-digit code the
 * approving app showed: the server alone (which could seal a key of its own to the new device)
 * never has it. The approving app approves only when the user picked, among three sets of words,
 * the ones the new device shows.
 */

/** What polling a sign-in request ended with (never [Pending] from [DeviceLoginFlow.await]). */
sealed interface DeviceLoginPoll {
    data object Pending : DeviceLoginPoll

    /** Approved: the password sign-in's session answer plus `sealed_key`. */
    data class Approved(val session: JsonObject) : DeviceLoginPoll

    /** Approved, but the account has two-step login and this device isn't remembered. */
    data class TwoFactor(val token: String, val providers: List<String>) : DeviceLoginPoll

    /** Denied, expired, already used or gone: [message] says so. */
    data class Ended(val message: String) : DeviceLoginPoll
}

/** What a code typed on the new device came to ([DeviceLogin.check]). */
sealed interface CodeCheck {
    /** The approving app's code: the sign-in can finish. */
    data object Confirmed : CodeCheck

    /** Another code: [message] says how many tries are left. */
    data class Wrong(val message: String) : CodeCheck

    /** Not a 6-digit code: not counted. */
    data class NotACode(val message: String) : CodeCheck

    /** The third wrong code: the sign-in is stopped for good ([message] says what to do). */
    data class Stopped(val message: String) : CodeCheck
}

/** The new device's side, as plain data and wording. */
object DeviceLogin {
    /** The `/api/config` feature. */
    const val FEATURE = "login_with_device"

    /** The poll's header for the access code (never in the URL: proxies log query strings). */
    const val ACCESS_CODE_HEADER = "X-PassAuth-Access-Code"

    /** Seconds before each poll, then [MAX_DELAY] after them. */
    private val DELAYS = longArrayOf(2, 2, 2, 3, 3, 4, 5, 6, 8)
    const val MAX_DELAY = 10L

    /** Seconds to wait after a 429 that didn't say how long. */
    const val RATE_LIMIT_WAIT = 10L

    /** How long a request lives on the server (15 minutes): this device never waits longer, whatever the server says. */
    const val LIFETIME = 15 * 60L

    /** Polling goes on this long past the request's time while the server can't say it expired (unreachable). */
    const val EXPIRY_GRACE = 60L

    const val LINK = "Sign in with another device"
    const val TITLE = "Sign in with another device"
    const val INTRO = "Approve the sign-in on a device where you're already signed in to PassAuth. You don't need your master password here."
    const val SEND = "Send request"
    const val WAIT_TITLE = "Approve on your other device"
    const val WAITING = "Waiting for approval…"

    const val DENIED = "The sign-in was denied on your other device."
    const val EXPIRED = "The request expired. Start again to get new words."
    const val USED = "This request was already used. Start again."
    const val GONE = "This request is no longer valid. Start again."
    const val DISABLED = "Your server doesn't allow signing in with another device."
    const val UNVERIFIED = "This approval couldn't be verified on this device. Start again."

    const val CODE_TITLE = "Confirm the sign-in"
    const val CODE_INTRO = "Your other device approved the sign-in. Enter the 6-digit code shown on your other device."
    const val CODE_PROMPT = "Enter the 6-digit code shown on your other device."
    const val CODE_LABEL = "6-digit code"
    const val TOO_MANY_CODES =
        "Too many wrong codes, so this sign-in was stopped. If you didn't approve it on your other device, change your master password."

    /** "That code doesn't match. 2 tries left." */
    fun wrongCode(left: Int) = "That code doesn't match. ${if (left == 1) "1 try" else "$left tries"} left."

    /** The waiting screen's instruction: the other device asks which words this one shows. */
    fun waitText(email: String) =
        "On a device where you're signed in as $email, open PassAuth. When it asks which words this device shows, pick these:"

    /** 32 random bytes in base64url without padding (43 characters): the code only this device knows. */
    fun accessCode(random: SecureRandom = SecureRandom()): String =
        Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(32).also(random::nextBytes))

    /** Seconds to wait before poll number [attempt] (0-based). */
    fun pollDelay(attempt: Int): Long = DELAYS.getOrElse(attempt) { MAX_DELAY }

    /** The time left until [expiresAt] (unix seconds) as "14:59", "0:05", never below "0:00". */
    fun countdown(expiresAt: Long, nowSeconds: Long): String {
        val left = maxOf(0L, expiresAt - nowSeconds)
        return String.format(Locale.ROOT, "%d:%02d", left / 60, left % 60)
    }

    fun expiresIn(expiresAt: Long, nowSeconds: Long) = "Expires in ${countdown(expiresAt, nowSeconds)}"

    /**
     * When a request made at [madeAt] expires, by this device's clock: the time the server gives it
     * ([serverExpiresAt] on the server's clock, read at [now]), but never more than [LIFETIME] after
     * it was made. A time already past, or none, counts as [LIFETIME] too: a server can't keep this
     * device waiting (and polling) for longer.
     */
    fun deadline(serverExpiresAt: Long?, madeAt: Long, now: Long): Long {
        val cap = madeAt + LIFETIME
        val left = serverExpiresAt?.minus(now)?.takeIf { it > 0 } ?: return cap
        return minOf(now + left, cap)
    }

    /** `POST /auth/requests`: [device] is the password sign-in's `device` object. */
    fun requestBody(email: String, publicKey: String, accessCode: String, device: JsonObject, rememberToken: String?): JsonObject = buildJsonObject {
        put("email", email.trim())
        put("public_key", publicKey)
        put("access_code", accessCode)
        put("device_id", (device["id"] as? JsonPrimitive)?.contentOrNull.orEmpty())
        put("device_name", (device["name"] as? JsonPrimitive)?.contentOrNull.orEmpty())
        put("device_kind", (device["kind"] as? JsonPrimitive)?.contentOrNull.orEmpty())
        if (!rememberToken.isNullOrEmpty()) put("remember_token", rememberToken)
    }

    /** An answer of `GET /auth/requests/{id}`. An unknown status counts as still pending (until it expires). */
    fun parsePoll(o: JsonObject): DeviceLoginPoll = when (o.str("status")) {
        "denied" -> DeviceLoginPoll.Ended(DENIED)
        "expired" -> DeviceLoginPoll.Ended(EXPIRED)
        "used" -> DeviceLoginPoll.Ended(USED)
        "approved" -> if (o.bool("two_factor_required")) {
            DeviceLoginPoll.TwoFactor(o.str("two_factor_token"), (o["providers"] as? JsonArray).orEmpty().mapNotNull { (it as? JsonPrimitive)?.contentOrNull })
        } else {
            DeviceLoginPoll.Approved(o)
        }
        else -> DeviceLoginPoll.Pending
    }

    private val REQUEST_ID = Regex("[A-Za-z0-9-]{1,64}")

    /** A request id as the server makes them (a UUID): anything else never goes into a path. */
    fun isRequestId(id: String) = REQUEST_ID.matches(id)

    /** The server turned the feature off (403 `login_with_device_disabled`). */
    fun isDisabled(e: Throwable): Boolean = e is ApiException && e.status == 403 && e.hasCode("login_with_device_disabled")

    /**
     * Check [code] (as typed: spaces and hyphens are fine) against an approval that came with the
     * sign-in (the core's ApprovedLogin, which unlocks nothing before it accepted the code). A wrong
     * code says how many tries are left, the third stops the sign-in for good, and anything but six
     * digits isn't counted.
     */
    fun check(approval: ApprovedLoginInterface, code: String): CodeCheck = try {
        approval.confirm(code)
        CodeCheck.Confirmed
    } catch (_: CoreException.TooManyWrongCodes) {
        CodeCheck.Stopped(TOO_MANY_CODES)
    } catch (_: CoreException.WrongCode) {
        val left = approval.attemptsLeft().toInt()
        if (left <= 0) CodeCheck.Stopped(TOO_MANY_CODES) else CodeCheck.Wrong(wrongCode(left))
    } catch (_: CoreException.Invalid) {
        CodeCheck.NotACode(CODE_PROMPT)
    }

    /**
     * This device's Secret Keys after a sign-in approved with [received] (once the code was
     * confirmed): it is kept only under the email typed on this device ([typedEmail]), only when the
     * server signed in that same account ([sessionEmail]), and never over a different key already
     * kept for that email (the kept one stays). Otherwise [kept] comes back unchanged.
     */
    fun keepSecretKey(kept: Map<String, String>, received: String?, typedEmail: String, sessionEmail: String): Map<String, String> {
        val key = received?.takeIf { it.isNotBlank() } ?: return kept
        val email = typedEmail.trim().lowercase()
        if (email.isEmpty() || email != sessionEmail.trim().lowercase()) return kept
        val old = kept[email]
        return if (old == null || old == key) kept + (email to key) else kept
    }
}

/** The new device's requests to its server (no session). */
interface DeviceLoginTransport {
    /** `POST /auth/requests`. */
    suspend fun create(body: JsonObject): JsonObject

    /** `GET /auth/requests/{id}` with the access code in [DeviceLogin.ACCESS_CODE_HEADER]. */
    suspend fun poll(id: String, accessCode: String): JsonObject
}

/**
 * The new device's requests through the app's API client ([SecurityTransport]: calls pinned to
 * the account record): no session, the access code in [DeviceLogin.ACCESS_CODE_HEADER].
 */
class ApiDeviceLoginTransport(private val api: SecurityTransport) : DeviceLoginTransport {
    override suspend fun create(body: JsonObject): JsonObject = api.call("/auth/requests", body, "POST", false, emptyMap()).jsonObject

    override suspend fun poll(id: String, accessCode: String): JsonObject =
        api.call("/auth/requests/$id", null, "GET", false, mapOf(DeviceLogin.ACCESS_CODE_HEADER to accessCode)).jsonObject
}

/**
 * One sign-in request of a new device: [start] it, show the words of the request's key, then
 * [await] the other device's answer (polling with growing delays, as long as it lives).
 */
class DeviceLoginFlow(
    private val transport: DeviceLoginTransport,
    private val nowSeconds: () -> Long = { System.currentTimeMillis() / 1000 },
    private val sleep: suspend (seconds: Long) -> Unit = { delay(it * 1000) },
) {
    /**
     * A request the server took: its id and when it expires, by this device's clock and never more
     * than [DeviceLogin.LIFETIME] after it was made ([DeviceLogin.deadline]).
     */
    data class Started(val id: String, val expiresAt: Long)

    /** Ask to sign in to [email] with the request key's [publicKey]; the server's `fingerprint_phrase` is never used. */
    suspend fun start(email: String, publicKey: String, accessCode: String, device: JsonObject, rememberToken: String?): Started {
        val madeAt = nowSeconds()
        val o = try {
            transport.create(DeviceLogin.requestBody(email, publicKey, accessCode, device, rememberToken))
        } catch (e: ApiException) {
            if (DeviceLogin.isDisabled(e)) throw UserException(DeviceLogin.DISABLED)
            throw e
        }
        val id = o.str("id").takeIf { DeviceLogin.isRequestId(it) } ?: throw UserException(DeviceLogin.GONE)
        val serverExpiresAt = (o["expires_at"] as? JsonPrimitive)?.takeIf { !it.isString }?.longOrNull
        return Started(id, DeviceLogin.deadline(serverExpiresAt, madeAt, nowSeconds()))
    }

    /**
     * Poll until the request ends: approved (with a session, or two-step login first) or
     * [DeviceLoginPoll.Ended]. Waits [DeviceLogin.pollDelay] before each poll, a 429's
     * `Retry-After` when rate-limited; keeps going through network and server errors until the
     * request is past its time ([expiresAt], this device's clock, plus [DeviceLogin.EXPIRY_GRACE]).
     * Other errors (a disabled account, …) are thrown as they are.
     */
    suspend fun await(id: String, accessCode: String, expiresAt: Long): DeviceLoginPoll {
        var attempt = 0
        while (true) {
            sleep(DeviceLogin.pollDelay(attempt++))
            if (nowSeconds() > expiresAt + DeviceLogin.EXPIRY_GRACE) return DeviceLoginPoll.Ended(DeviceLogin.EXPIRED)
            val answer = try {
                transport.poll(id, accessCode)
            } catch (e: CancellationException) {
                throw e
            } catch (e: ApiException) {
                when {
                    e.isRateLimited -> {
                        sleep(e.retryAfter?.takeIf { it > 0 } ?: DeviceLogin.RATE_LIMIT_WAIT)
                        continue
                    }
                    e.status >= 500 -> continue
                    e.status == 404 -> return DeviceLoginPoll.Ended(DeviceLogin.GONE)
                    DeviceLogin.isDisabled(e) -> return DeviceLoginPoll.Ended(DeviceLogin.DISABLED)
                    else -> throw e
                }
            } catch (_: UserException) {
                // The server couldn't be reached: try again with the next delay.
                continue
            }
            val poll = DeviceLogin.parsePoll(answer)
            if (poll != DeviceLoginPoll.Pending) return poll
        }
    }
}

// ------------------------------------------------------------ the approving app

/** A sign-in request from a new device waiting for this account's answer (`GET /account/auth-requests`). */
data class AuthRequest(
    val id: String,
    /** The new device's X25519 key (base64url): the words are worked out from it here. */
    val publicKey: String,
    /**
     * A value sealed to this account's key; opening it proves the approval comes from an app that
     * holds the keys. The server seals it again for every listing, so its text changes while the
     * value inside doesn't: never compared, the frozen one is opened.
     */
    val challenge: String,
    /** What the new device calls itself: a claim, shown cleaned ([DeviceApprovals.device]). */
    val deviceName: String,
    val deviceKind: String,
    /** The asking app (`X-PassAuth-Client`), when the server recorded it. */
    val client: String?,
    /** The address the request came from, when the server keeps addresses. */
    val ip: String?,
    val createdAt: Long,
    val expiresAt: Long,
) {
    override fun toString() = "AuthRequest($id, $deviceKind)"
}

/** The unlocked account's part of an approval (the core's `Account`; faked in tests). */
interface ApprovalCrypto {
    /**
     * Approve request [requestId] after the user picked [chosenPhrase] as the words the new device
     * shows: the account key (and [secretKey] when given) sealed to [publicKey], and the code to
     * show. Throws the core's `PhraseMismatch` when those aren't the words of [publicKey].
     */
    fun approve(publicKey: String, requestId: String, chosenPhrase: String, secretKey: String?): LoginApproval

    /** The request's challenge opened with the account's private key. */
    fun proof(challenge: String, requestId: String): String
}

/** [ApprovalCrypto] with the unlocked account from the Rust core. */
class AccountApprovalCrypto(private val account: io.passauth.core.Account) : ApprovalCrypto {
    override fun approve(publicKey: String, requestId: String, chosenPhrase: String, secretKey: String?): LoginApproval =
        account.approveLoginRequest(publicKey, requestId, chosenPhrase, secretKey)

    override fun proof(challenge: String, requestId: String): String = account.openLoginChallenge(challenge, requestId)
}

/** The approving app's requests (signed in) through the app's API client. */
class AuthRequestApi(private val api: SecurityTransport) {
    /** `GET /account/auth-requests`, read with [DeviceApprovals.parse]. */
    suspend fun list(nowSeconds: Long): List<AuthRequest> = DeviceApprovals.parse(api.call("/account/auth-requests", null, "GET", true, emptyMap()), nowSeconds)

    /** `POST /account/auth-requests/{id}` with [DeviceApprovals.DENY] or a [PreparedApproval.Approve]'s body. */
    suspend fun answer(request: AuthRequest, body: JsonObject) {
        api.call("/account/auth-requests/${request.id}", body, "POST", true, emptyMap())
    }
}

/** An approval ready to send ([DeviceApprovals.prepare]), or the words picked weren't the request's. */
sealed interface PreparedApproval {
    /** The answer's [body], and the [code] to show for the new device. */
    data class Approve(val body: JsonObject, val code: String) : PreparedApproval {
        override fun toString() = "Approve(…)"
    }

    data object Mismatch : PreparedApproval
}

/** The approving app's side: reading the requests, answering one, and the sheet's wording. */
object DeviceApprovals {

    const val TITLE = "Sign-in request"
    const val DEVICE = "Device (as it calls itself)"
    const val APP = "App"
    const val ADDRESS = "IP address"
    const val REQUESTED = "Requested"
    const val NO_NAME = "No name given"
    const val QUESTION = "Which words does the new device show?"
    const val HELP = "Choosing the words approves the sign-in: that device can then open your vault without your master password. " +
        "If you didn't ask to sign in, or the new device shows other words, choose None of these."
    const val CANNOT_CHECK = "This request can't be checked, so it can't be approved. Choose None of these, then start again on the new device."
    const val NONE = "None of these"
    const val NOT_NOW = "Not now"
    const val CHANGED_TITLE = "Sign-in request closed"
    const val CHANGED = "This request changed, so it was closed. If you're signing in on a new device, start again there."
    const val MISMATCH_TITLE = "Sign-in request denied"
    const val MISMATCH = "Those aren't the words for this request, so it was denied."
    const val UNCHECKED = "This request couldn't be checked, so it wasn't approved."
    const val APPROVED_TITLE = "Sign-in approved"
    const val CODE = "Enter this code on the new device"
    const val CODE_HELP = "Only that device needs it. It opens your vault there once the code is in."
    const val DONE = "Done"
    const val DENIED = "Sign-in denied."
    const val ANSWERED_ELSEWHERE = "This sign-in was already answered on another device."
    const val EXPIRED = "This sign-in request has expired."

    /** How many sets of words the sheet offers (one of them is the request's). */
    const val CHOICES = 3

    /** Device names, apps and addresses are the new device's claims: shown cleaned and cut to this many characters. */
    const val CLAIM_MAX = 64

    /** The words can be picked only this long after the sheet appeared (or the app came back on screen). */
    const val CHOICE_DELAY_MS = 1000L

    /** "A device is asking to sign in to alex@example.com." (what it calls itself is listed apart, as a claim). */
    fun body(email: String) = "A device is asking to sign in to $email."

    /** The name the new device gave itself, cleaned and cut short ([ShownText]). */
    fun device(r: AuthRequest): String = ShownText.clean(r.deviceName, CLAIM_MAX).ifEmpty { NO_NAME }

    /** The asking app in the sessions screen's words, else its device kind; cleaned and cut short (both are claims). */
    fun app(r: AuthRequest): String = ShownText.clean(SessionText.client(r.client) ?: SessionText.kind(r.deviceKind), CLAIM_MAX)

    /** The address the request came from, when the server keeps it. */
    fun address(r: AuthRequest): String? = ShownText.clean(r.ip, CLAIM_MAX).ifEmpty { null }

    /** "123 456": the code, easy to read out and type. */
    fun groupedCode(code: String): String = if (code.length == 6) "${code.take(3)} ${code.drop(3)}" else code

    /** "Just now", "1 minute ago", "3 minutes ago", "2 hours ago". */
    fun requested(createdAt: Long, nowSeconds: Long): String {
        val s = maxOf(0L, nowSeconds - createdAt)
        return when {
            s < 60 -> "Just now"
            s < 3600 -> (s / 60).let { m -> "$m minute${if (m == 1L) "" else "s"} ago" }
            else -> (s / 3600).let { h -> "$h hour${if (h == 1L) "" else "s"} ago" }
        }
    }

    /**
     * The [CHOICES] sets of words to pick from for a request's key, in random order (the core's
     * `loginPhraseChoices`: one is the key's own, the others differ from it in every word); empty
     * when the key can't be read.
     */
    fun choices(publicKey: String): List<String> = try {
        loginPhraseChoices(publicKey, CHOICES.toUInt()).takeIf { it.size == CHOICES && it.toSet().size == CHOICES }.orEmpty()
    } catch (_: Exception) {
        emptyList()
    }

    /**
     * `{requests: [...]}`, read leniently: entries without what an answer needs (an id, the key,
     * the challenge) or already expired are left out; newest first. The server's
     * `fingerprint_phrase` is never read: the words come from the key this app holds.
     */
    fun parse(value: JsonElement?, nowSeconds: Long): List<AuthRequest> {
        val list = ((value as? JsonObject)?.get("requests") as? JsonArray).orEmpty()
        return list.mapNotNull { e ->
            val o = e as? JsonObject ?: return@mapNotNull null
            fun text(key: String) = (o[key] as? JsonPrimitive)?.takeIf { it.isString }?.content
            fun number(key: String) = (o[key] as? JsonPrimitive)?.takeIf { !it.isString }?.longOrNull
            val id = text("id")?.takeIf(DeviceLogin::isRequestId) ?: return@mapNotNull null
            val key = text("public_key")?.takeIf { it.isNotEmpty() } ?: return@mapNotNull null
            val challenge = text("challenge")?.takeIf { it.isNotEmpty() } ?: return@mapNotNull null
            val expiresAt = number("expires_at")?.takeIf { it > nowSeconds } ?: return@mapNotNull null
            AuthRequest(
                id = id,
                publicKey = key,
                challenge = challenge,
                deviceName = text("device_name").orEmpty(),
                deviceKind = text("device_kind").orEmpty(),
                client = text("client")?.takeIf { it.isNotBlank() },
                ip = text("ip")?.takeIf { it.isNotBlank() },
                createdAt = number("created_at") ?: 0,
                expiresAt = expiresAt,
            )
        }.sortedByDescending { it.createdAt }
    }

    /** The answer that denies a request ("None of these"): it needs nothing from the account. */
    val DENY: JsonObject = buildJsonObject { put("approve", false) }

    /**
     * Approve [r] (as frozen when its sheet opened) with the words the user picked: the core seals
     * the account key (with the Secret Key this app keeps, so the new device can unlock with the
     * master password later) to the request's key only when [chosenPhrase] is that key's words, and
     * gives the code the new device needs; the request's challenge, opened with the account's key,
     * proves the answer comes from an app that holds the keys. Other words: [PreparedApproval.Mismatch].
     */
    fun prepare(r: AuthRequest, chosenPhrase: String, crypto: ApprovalCrypto, secretKey: String?): PreparedApproval {
        val approval = try {
            crypto.approve(r.publicKey, r.id, chosenPhrase, secretKey)
        } catch (_: CoreException.PhraseMismatch) {
            return PreparedApproval.Mismatch
        }
        val body = buildJsonObject {
            put("approve", true)
            put("sealed_key", approval.sealed)
            put("proof", crypto.proof(r.challenge, r.id))
        }
        return PreparedApproval.Approve(body, approval.code)
    }

    /** Plain words for an answer that didn't go through, or null for any other error. */
    fun errorMessage(e: Throwable): String? = when {
        e is CoreException -> UNCHECKED
        e !is ApiException -> null
        e.status == 409 -> "This request was already answered on another device."
        e.status == 400 && e.hasCode("expired") -> "This request expired."
        e.status == 404 -> "This request is no longer there."
        else -> null
    }
}

// ------------------------------------------------------- the approving app's queue

/** An answer on its way for the request on screen. */
enum class Answering { Approve, Deny }

/** Why the shown sheet closed, when that must be read before anything else comes up. */
enum class Closed(val title: String, val text: String) {
    /** A listing dropped the shown request or gave its id another key. */
    Changed(DeviceApprovals.CHANGED_TITLE, DeviceApprovals.CHANGED),

    /** The words picked weren't the request's: it was denied. */
    Mismatch(DeviceApprovals.MISMATCH_TITLE, DeviceApprovals.MISMATCH),
}

/**
 * A request as it was when its sheet opened: everything the sheet shows and the answer uses comes
 * from this copy, never from a newer listing. [choices]: the sets of words to pick from (empty when
 * the key can't be read); [code]: approved here, the code to enter on the new device (shown until
 * Done); [answering]: an answer on its way.
 */
data class ShownRequest(
    val request: AuthRequest,
    val choices: List<String>,
    val code: String? = null,
    val answering: Answering? = null,
) {
    /** Answered here, or being answered: listings and other devices' answers leave it on screen. */
    val handled: Boolean get() = code != null || answering != null

    override fun toString() = "ShownRequest(${request.id}, code=${code != null}, $answering)"
}

/** A step of the queue: its new state, and a note for the snackbar (or none). */
data class QueueStep(val queue: ApprovalQueue, val note: String? = null)

/**
 * The approving app's sign-in requests: shown one at a time, each frozen when its sheet opens
 * ([ShownRequest]: its key, challenge and claims). A newer request never takes the place of the one
 * on screen: it waits in line until that one is answered or put off. A listing that changes the
 * shown request (another key under its id) or drops it closes the sheet with a note ([closed])
 * instead of showing anything new; the request isn't shown again by itself. Pure:
 * [AuthRequestInbox] runs the steps.
 */
data class ApprovalQueue(
    /** The account the requests are for (a listing for another account starts afresh). */
    val account: String? = null,
    /** The latest listing's requests still waiting, newest first. */
    val requests: List<AuthRequest> = emptyList(),
    /** Put off ("Not now") or closed because they changed: not shown again by themselves in this run. */
    val dismissed: Set<String> = emptySet(),
    val shown: ShownRequest? = null,
    /** Why the shown sheet closed (it changed, or the words picked weren't its): shown until read, nothing else comes up meanwhile. */
    val closed: Closed? = null,
) {
    /**
     * A fresh listing of [account]'s requests at [now]: the waiting ones are replaced, the shown one
     * stays frozen, or closes when the listing dropped it or gives its id another key. The
     * challenge's text is never compared: the server seals it again for every listing (a fresh
     * ephemeral key, the same value inside), so it differs each time; the frozen one still opens.
     */
    fun listed(account: String, fresh: List<AuthRequest>, now: Long): QueueStep {
        val base = if (account != this.account) ApprovalQueue(account = account, dismissed = dismissed) else this
        val waiting = fresh.filter { it.id !in base.dismissed }
        val s = base.shown
        if (s == null || s.handled) return QueueStep(base.copy(requests = waiting))
        val id = s.request.id
        val listed = fresh.firstOrNull { it.id == id }
        return when {
            listed == null && s.request.expiresAt <= now -> QueueStep(base.copy(requests = waiting, shown = null), DeviceApprovals.EXPIRED)
            listed == null || listed.publicKey != s.request.publicKey ->
                QueueStep(base.copy(requests = waiting.filter { it.id != id }, dismissed = base.dismissed + id, shown = null, closed = Closed.Changed))
            else -> QueueStep(base.copy(requests = waiting))
        }
    }

    /** Live sync says request [id] was answered: on another device (the sheet closes), or this app's own answer coming back. */
    fun answeredElsewhere(id: String): QueueStep {
        val rest = requests.filter { it.id != id }
        val s = shown
        if (s == null || s.request.id != id || s.handled) return QueueStep(copy(requests = rest, dismissed = dismissed + id))
        return QueueStep(copy(requests = rest, dismissed = dismissed + id, shown = null), DeviceApprovals.ANSWERED_ELSEWHERE)
    }

    /** "Not now": the sheet closes and the request isn't shown again by itself (it expires on the server). */
    fun putOff(id: String): QueueStep = QueueStep(
        copy(
            requests = requests.filter { it.id != id },
            dismissed = dismissed + id,
            shown = shown?.takeIf { it.request.id != id || it.handled },
        ),
    )

    /** An answer of [what] leaves for the shown request [id]; null when it isn't the one on screen or is answered already. */
    fun answering(id: String, what: Answering): ApprovalQueue? {
        val s = shown?.takeIf { it.request.id == id && !it.handled } ?: return null
        return copy(shown = s.copy(answering = what))
    }

    /** An answer that never left (cancelled): the sheet is as it was. */
    fun notAnswered(id: String): QueueStep =
        QueueStep(copy(shown = shown?.let { if (it.request.id == id && it.code == null) it.copy(answering = null) else it }))

    /** Approved here: its [code] shows until [done]; the request never comes up again. */
    fun approved(id: String, code: String): QueueStep = QueueStep(
        copy(
            requests = requests.filter { it.id != id },
            dismissed = dismissed + id,
            shown = shown?.let { if (it.request.id == id) it.copy(code = code, answering = null) else it },
        ),
    )

    /**
     * The sheet of request [id] closes: denied here ([answered], it never comes up again), or the
     * answer failed (a later listing brings back one still open).
     */
    fun finished(id: String, note: String? = null, answered: Boolean = true): QueueStep = QueueStep(
        copy(
            requests = requests.filter { it.id != id },
            dismissed = if (answered) dismissed + id else dismissed,
            shown = shown?.takeIf { it.request.id != id },
        ),
        note,
    )

    /** Done with the code of request [id]. */
    fun done(id: String): QueueStep = QueueStep(copy(shown = shown?.takeIf { it.request.id != id || it.code == null }))

    /** The shown request ran out of time before it was answered. */
    fun expired(id: String, now: Long): QueueStep {
        if (shown?.takeIf { it.request.id == id && !it.handled && it.request.expiresAt <= now } == null) return QueueStep(this)
        return QueueStep(copy(requests = requests.filter { it.id != id }, shown = null), DeviceApprovals.EXPIRED)
    }

    /** The words picked for request [id] weren't its own: it was denied, and the note shows until read. */
    fun mismatched(id: String): QueueStep = QueueStep(
        copy(
            requests = requests.filter { it.id != id },
            dismissed = dismissed + id,
            shown = shown?.takeIf { it.request.id != id },
            closed = Closed.Mismatch,
        ),
    )

    /** The note of a sheet that closed ([closed]) was read. */
    fun closedRead(): QueueStep = QueueStep(copy(closed = null))

    /** Locked, signed out or no feature: nothing to show. */
    fun clear(): QueueStep = QueueStep(ApprovalQueue(dismissed = dismissed))

    /**
     * Nothing on screen: the next request in line, frozen as it is now ([freeze] adds its words to
     * pick from). Never while a request is shown or a [closed] note waits.
     */
    fun next(now: Long, freeze: (AuthRequest) -> ShownRequest): ApprovalQueue {
        if (shown != null || closed != null) return this
        val r = requests.firstOrNull { it.id !in dismissed && it.expiresAt > now } ?: return this
        return copy(shown = freeze(r))
    }
}
