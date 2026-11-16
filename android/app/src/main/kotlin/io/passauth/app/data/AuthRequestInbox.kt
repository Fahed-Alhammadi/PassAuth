package io.passauth.app.data

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/** One listing of the active account's waiting sign-in requests. */
data class AuthRequestListing(val account: String, val requests: List<AuthRequest>)

/** Where the inbox gets requests and sends answers (the repository; faked in tests). */
interface AuthRequestSource {
    /** The active account's open requests, or null when there is nothing to ask (locked, no feature). */
    suspend fun list(): AuthRequestListing?

    /**
     * Approve [request] of [account] (as frozen when its sheet opened) with the words the user
     * picked: the code to show for the new device, or null when those weren't the request's words
     * (it was denied then).
     */
    suspend fun approve(account: String, request: AuthRequest, chosenPhrase: String): String?

    suspend fun deny(account: String, request: AuthRequest)
}

/** A note for the snackbar: the app's own sentence, or an answer that failed (the UI words it). */
sealed interface InboxNotice {
    data class Text(val text: String) : InboxNotice

    data class Failed(val error: Throwable) : InboxNotice
}

/**
 * Sign-in requests from new devices waiting for this app's answer (the approving side of "sign in
 * with another device"): listed after unlock, whenever live sync (re)connects and when the socket
 * says one arrived; shown one at a time (AppRoot's sheet), each frozen when its sheet opens
 * ([ApprovalQueue]); dropped when answered anywhere. Only the app lists them, never the autofill or
 * passkey services. Answers run here, so a screen rotation can't lose one half-way: the approval's
 * code lives in [queue] until Done.
 */
class AuthRequestInbox(
    private val source: AuthRequestSource,
    private val nowSeconds: () -> Long = { System.currentTimeMillis() / 1000 },
    /** The sets of words to pick from for a request's key ([DeviceApprovals.choices]). */
    private val choices: (publicKey: String) -> List<String> = DeviceApprovals::choices,
) {
    constructor(repo: VaultRepository) : this(
        object : AuthRequestSource {
            override suspend fun list() = repo.listAuthRequests()
            override suspend fun approve(account: String, request: AuthRequest, chosenPhrase: String) = repo.approveAuthRequest(account, request, chosenPhrase)
            override suspend fun deny(account: String, request: AuthRequest) = repo.denyAuthRequest(account, request)
        },
    )

    private val _queue = MutableStateFlow(ApprovalQueue())
    val queue: StateFlow<ApprovalQueue> = _queue.asStateFlow()

    private val _notices = MutableSharedFlow<InboxNotice>(extraBufferCapacity = 8)

    /** Why a sheet closed by itself (answered elsewhere, expired), denials, failed answers. */
    val notices: SharedFlow<InboxNotice> = _notices.asSharedFlow()

    private val listing = Mutex()
    private val lock = Any()

    /** The request on screen. */
    val shown: ShownRequest? get() = _queue.value.shown

    /** A request frozen as it is now, with its words to pick from. */
    private fun freeze(r: AuthRequest) = ShownRequest(r, choices(r.publicKey))

    /** Runs one step; then, when nothing is on screen, the next request in line comes up. */
    private fun step(f: (ApprovalQueue) -> QueueStep) {
        val note = synchronized(lock) {
            val s = f(_queue.value)
            _queue.value = s.queue.next(nowSeconds(), ::freeze)
            s.note
        }
        note?.let { _notices.tryEmit(InboxNotice.Text(it)) }
    }

    /** Ask the server again (one listing at a time); nothing to ask (locked, no feature) empties the list. */
    suspend fun refresh() = listing.withLock {
        val fresh = source.list()
        step { q -> if (fresh == null) q.clear() else q.listed(fresh.account, fresh.requests, nowSeconds()) }
    }

    /** Answered on another device (live sync), or this app's own answer coming back. */
    fun answered(id: String) = step { it.answeredElsewhere(id) }

    /** "Not now": hidden until the app starts again (it expires on the server). */
    fun putOff(id: String) = step { it.putOff(id) }

    /** Done with an approval's code. */
    fun done(id: String) = step { it.done(id) }

    /** The shown request's time ran out on screen. */
    fun expired(id: String) = step { it.expired(id, nowSeconds()) }

    /** The note of a sheet that closed ("request changed", "not its words") was read. */
    fun closedRead() = step { it.closedRead() }

    /** Locked, signed out or another account: nothing to show. */
    fun clear() = step { it.clear() }

    /**
     * The frozen request [id] and its account, now marked as being answered; null when it isn't on
     * screen, is answered already, or [phrase] isn't one of the words it offers.
     */
    private fun begin(id: String, what: Answering, phrase: String? = null): Pair<String, ShownRequest>? = synchronized(lock) {
        val q = _queue.value
        val account = q.account ?: return null
        val shown = q.shown ?: return null
        if (phrase != null && phrase !in shown.choices) return null
        _queue.value = q.answering(id, what) ?: return null
        account to shown
    }

    /**
     * Approve the request on screen ([id]) with the words the user picked, from its frozen copy:
     * its own words show the code until [done]; other words deny it ([Closed.Mismatch], a note to read).
     * A failed answer closes the sheet and comes as a notice (a later listing brings back a request
     * still open). Throws only when cancelled.
     */
    suspend fun approve(id: String, phrase: String) {
        val (account, shown) = begin(id, Answering.Approve, phrase) ?: return
        try {
            val code = source.approve(account, shown.request, phrase)
            step { if (code != null) it.approved(id, code) else it.mismatched(id) }
        } catch (e: CancellationException) {
            step { it.notAnswered(id) }
            throw e
        } catch (e: Exception) {
            step { it.finished(id, answered = false) }
            _notices.tryEmit(InboxNotice.Failed(e))
        }
    }

    /** "None of these": deny the request on screen ([id]). Failures as for [approve]. */
    suspend fun deny(id: String) {
        val (account, shown) = begin(id, Answering.Deny) ?: return
        try {
            source.deny(account, shown.request)
            step { it.finished(id, DeviceApprovals.DENIED) }
        } catch (e: CancellationException) {
            step { it.notAnswered(id) }
            throw e
        } catch (e: Exception) {
            step { it.finished(id, answered = false) }
            _notices.tryEmit(InboxNotice.Failed(e))
        }
    }
}
