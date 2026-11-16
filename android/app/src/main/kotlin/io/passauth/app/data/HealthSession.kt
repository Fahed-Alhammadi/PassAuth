package io.passauth.app.data

import java.util.concurrent.atomic.AtomicInteger
import io.passauth.core.estimateBits
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

/** What password health reads from the repository ([VaultRepository]; a fake in tests). */
interface HealthSource {
    /** The active account's decrypted vault; null while locked. */
    val vault: StateFlow<VaultData?>

    /** The active account's server's `/api/config` `features`, asked now; null when they couldn't be loaded. */
    suspend fun serverFeatures(): List<String>?

    /** Called whenever the decrypted vault is dropped (lock, log out, switching or adding an account). */
    var onVaultClosed: (() -> Unit)?
}

/**
 * Password health for the unlocked vault in this app session ([PasswordHealth] does the work), like
 * the web vault's `health-session.ts`. The report is worked out again only when the vault changes.
 * The breach check runs only when the user asks and the server allows it (feature `breach_check`),
 * with its own OkHttp client. The report, the check's results and the kept range answers stay in
 * memory and are dropped when the vault locks, signs out or the account changes
 * ([HealthSource.onVaultClosed]).
 */
class HealthSession(
    private val repo: HealthSource,
    private val checker: BreachChecker,
    private val scope: CoroutineScope,
    /** The strength estimate (the core's; tests stub it). */
    private val bits: (String) -> Double = ::estimateBits,
) {
    enum class Status { Idle, Checking, Done, Failed }

    /** [Unknown]: the server's settings couldn't be loaded. */
    enum class Availability { Loading, On, Off, Unknown }

    data class State(
        val status: Status = Status.Idle,
        /** While checking: distinct passwords checked so far, of [total]. */
        val done: Int = 0,
        val total: Int = 0,
        /** Times seen per password, from the last finished check; passwords added or changed since are missing. */
        val results: Map<String, Int>? = null,
        /** When [results] came in (ms since the epoch). */
        val checkedAt: Long? = null,
        /** Why the last check stopped, in plain words. */
        val error: String? = null,
        val availability: Availability = Availability.Loading,
    ) {
        override fun toString() = "State(status=$status, done=$done, total=$total, results=${results?.size}, availability=$availability)"
    }

    private val _state = MutableStateFlow(State())
    val state: StateFlow<State> = _state.asStateFlow()

    /** Bumped when the vault closes: a check or a settings request started before that is dropped. */
    private val generation = AtomicInteger(0)

    @Volatile
    private var memo: Pair<List<Entry>, HealthReport<Entry>>? = null

    init {
        repo.onVaultClosed = { clear() }
    }

    /** Weak and reused passwords in [v] (every vault the user can read); the same entries give back the same report. */
    fun report(v: VaultData): HealthReport<Entry> {
        memo?.let { (entries, report) -> if (entries === v.entries) return report }
        val report = PasswordHealth.analyze(v.entries, bits)
        memo = v.entries to report
        return report
    }

    /** Whether the server allows the breach check (asked each time the page opens). */
    suspend fun loadAvailability() {
        val gen = generation.get()
        _state.update { if (it.availability == Availability.Unknown) it.copy(availability = Availability.Loading) else it }
        val features = repo.serverFeatures()
        if (gen != generation.get()) return
        _state.update { it.copy(availability = availabilityOf(features)) }
    }

    private fun availabilityOf(features: List<String>?) = when {
        features == null -> Availability.Unknown
        PasswordHealth.BREACH_CHECK_FEATURE in features -> Availability.On
        else -> Availability.Off
    }

    /**
     * Check the password of every login the user can read against Have I Been Pwned, if the
     * server allows it. A previous check's results stay until this one finishes.
     */
    fun check() {
        if (repo.vault.value == null) return
        val gen = generation.get()
        var started = false
        _state.update {
            started = it.status != Status.Checking
            if (started) it.copy(status = Status.Checking, done = 0, total = 0, error = null) else it
        }
        if (!started) return
        scope.launch {
            val features = repo.serverFeatures()
            if (gen != generation.get()) return@launch
            when (availabilityOf(features)) {
                Availability.Unknown, Availability.Loading -> return@launch fail(HealthText.NO_CONFIG, gen)
                // Switched off since the page opened: the page now says so instead of the button.
                Availability.Off -> return@launch _state.update { it.copy(status = Status.Idle, availability = Availability.Off) }
                Availability.On -> _state.update { it.copy(availability = Availability.On) }
            }
            val v = repo.vault.value ?: return@launch fail(HealthText.STOPPED, gen)
            val passwords = report(v).logins.map { it.item.login?.password.orEmpty() }
            try {
                val found = checker.check(passwords) { done, total ->
                    if (gen == generation.get()) _state.update { it.copy(done = done, total = total) }
                }
                if (gen == generation.get()) {
                    _state.update { it.copy(status = Status.Done, results = found, checkedAt = System.currentTimeMillis()) }
                }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                fail(HealthText.explain(e), gen)
            }
        }
    }

    private fun fail(message: String, gen: Int) {
        if (gen == generation.get()) _state.update { it.copy(status = Status.Failed, error = message) }
    }

    /** The vault closed: stop a running check and forget the report, results and kept answers. */
    fun clear() {
        generation.incrementAndGet()
        checker.clear()
        memo = null
        _state.value = State()
    }
}
