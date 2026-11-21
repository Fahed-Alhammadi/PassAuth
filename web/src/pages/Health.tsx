import { useEffect, useMemo, useRef, type ReactNode } from "react";
import { Link } from "react-router";
import { Icon, SiteIcon } from "../components/ui";
import {
  checkForBreaches,
  useBreachCheck,
  useBreachCheckAvailability,
  useHealthReport,
  type BreachCheck,
  type BreachCheckAvailability,
} from "../lib/health-session";
import { clientName } from "../lib/platform";
import { useSiteIconsShown } from "../lib/site-icons";
import { siteHost, type VaultEntry } from "../lib/types";
import { useVault, type Vault } from "../lib/vault";
import { DuplicatesSection } from "./Duplicates";
import { MatchingSection } from "./Matching";
import { filterPath } from "./Shell";
import "../styles/tools.css";

const fmt = (n: number) => n.toLocaleString();
const count = (n: number, one: string, many: string) => `${fmt(n)} ${n === 1 ? one : many}`;
const passwordOf = (e: VaultEntry) => e.item.login?.password ?? "";
const byName = (a: VaultEntry, b: VaultEntry) => (a.item.name || "Untitled").localeCompare(b.item.name || "Untitled", undefined, { sensitivity: "base" });

/** Where a row opens: the item in the vault, in its editor when the user can change it; Back returns here. */
export interface HealthLinkState {
  from: "/health";
  edit: boolean;
}

/** Weak, reused and exposed passwords across every vault the user can read. */
export function HealthPage() {
  const { logins, weak, reused } = useHealthReport();
  const check = useBreachCheck();
  const availability = useBreachCheckAvailability();
  const results = check.results;

  const exposed = useMemo(() => {
    if (!results) return [];
    const seen = (e: VaultEntry) => results.get(passwordOf(e)) ?? 0;
    return logins.filter((e) => seen(e) > 0).sort((a, b) => seen(b) - seen(a) || byName(a, b));
  }, [logins, results]);
  const unchecked = results ? logins.filter((e) => !results.has(passwordOf(e))).length : 0;
  const reusedLogins = reused.reduce((n, group) => n + group.length, 0);
  const weakSorted = useMemo(() => [...weak].sort(byName), [weak]);

  const intro = (
    <header className="page-head">
      <h1>Password health</h1>
      <p>
        Find the logins to fix first: passwords exposed in a data breach, used for more than one login, or easy to guess. Weak and reused passwords
        are found in {clientName()}, without sending anything.
      </p>
    </header>
  );

  if (logins.length === 0) {
    return (
      <div className="page">
        <div className="page-inner">
          {intro}
          <div className="card empty">
            <span className="tile" aria-hidden="true">
              <Icon name="shield" size={22} />
            </span>
            <p className="empty-title">No passwords to check yet</p>
            <p>When your logins have passwords, this page shows which ones are weak, reused or exposed in a data breach.</p>
            <div className="empty-actions">
              <Link className="btn" to={`${filterPath("login")}/new-login`}>
                <Icon name="plus" /> Add a login
              </Link>
              <Link className="btn btn-text" to="/import">
                Import from another app
              </Link>
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="page">
      <div className="page-inner">
        {intro}

        <ul className="stat-grid health-summary" aria-label="Summary">
          {(results || (availability !== "off" && availability !== "unknown")) && (
            <li className="stat">
              {results ? (
                <span className={`num${exposed.length ? " is-bad" : ""}`}>{fmt(exposed.length)}</span>
              ) : (
                <span className="num" aria-hidden="true">
                  –
                </span>
              )}
              <span className="lbl">{results ? "Exposed" : "Exposed: not checked yet"}</span>
            </li>
          )}
          <li className="stat">
            <span className={`num${reusedLogins ? " is-warn" : ""}`}>{fmt(reusedLogins)}</span>
            <span className="lbl">Reused</span>
          </li>
          <li className="stat">
            <span className={`num${weak.length ? " is-warn" : ""}`}>{fmt(weak.length)}</span>
            <span className="lbl">Weak</span>
          </li>
          <li className="stat">
            <span className="num">{fmt(logins.length)}</span>
            <span className="lbl">{logins.length === 1 ? "Login with a password" : "Logins with a password"}</span>
          </li>
        </ul>

        <ExposedSection check={check} availability={availability} exposed={exposed} unchecked={unchecked} total={logins.length} />

        <DuplicatesSection />

        <MatchingSection />

        <section className="card" aria-labelledby="health-reused">
          <div className="card-head">
            <div className="card-title">
              <h2 id="health-reused">Reused passwords</h2>
              {reusedLogins > 0 && <span className="badge">{fmt(reusedLogins)}</span>}
            </div>
          </div>
          <p className="card-text">When one site leaks a password that other logins use too, all of them are at risk. Give each login its own password.</p>
          {reused.length === 0 ? (
            <AllClear title="No reused passwords" text="Every login has its own password." />
          ) : (
            reused.map((group, n) => (
              <div className="stack-s" key={group[0].id}>
                <h3 className="health-group" id={`health-reuse-${n}`}>
                  Same password in {count(group.length, "login", "logins")}
                </h3>
                <LoginRows entries={[...group].sort(byName)} labelledBy={`health-reuse-${n}`} />
              </div>
            ))
          )}
        </section>

        <section className="card" aria-labelledby="health-weak">
          <div className="card-head">
            <div className="card-title">
              <h2 id="health-weak">Weak passwords</h2>
              {weak.length > 0 && <span className="badge">{fmt(weak.length)}</span>}
            </div>
          </div>
          <p className="card-text">These passwords are short or use few kinds of characters, so they're easy to guess. Replace them with generated ones.</p>
          {weakSorted.length === 0 ? (
            <AllClear title="No weak passwords" text="Every password is long and varied enough." />
          ) : (
            <LoginRows entries={weakSorted} labelledBy="health-weak" />
          )}
        </section>
      </div>
    </div>
  );
}

function ExposedSection({
  check,
  availability,
  exposed,
  unchecked,
  total,
}: {
  check: BreachCheck;
  availability: BreachCheckAvailability;
  exposed: VaultEntry[];
  unchecked: number;
  total: number;
}) {
  const { status, results } = check;
  const checking = status === "checking";
  const allowed = availability === "on";
  // The button that started the check is disabled or gone when it ends: bring focus back to the section.
  const heading = useRef<HTMLHeadingElement>(null);
  const wasChecking = useRef(false);
  useEffect(() => {
    if (checking) wasChecking.current = true;
    else if (wasChecking.current) {
      wasChecking.current = false;
      if (!document.activeElement || document.activeElement === document.body) heading.current?.focus();
    }
  }, [checking]);
  const pct = check.total ? Math.round((check.done / check.total) * 100) : 0;
  // Screen readers hear the progress in steps of a quarter, not after every request.
  const announcement = checking
    ? check.total
      ? `Checking ${count(check.total, "password", "passwords")}, ${Math.floor((check.done / check.total) * 4) * 25}% done.`
      : "Starting the check."
    : status === "done"
      ? exposed.length
        ? `Check finished. ${count(exposed.length, "login uses a password", "logins use passwords")} found in data breaches.`
        : "Check finished. No exposed passwords found."
      : "";

  return (
    <section className="card" aria-labelledby="health-exposed">
      <div className="card-head">
        <div className="card-title">
          <h2 id="health-exposed" ref={heading} tabIndex={-1}>
            Exposed in data breaches
          </h2>
          {results && <span className={exposed.length ? "badge badge-warn" : "badge badge-ok"}>{exposed.length ? fmt(exposed.length) : "None found"}</span>}
        </div>
        {results && allowed && (
          <button type="button" className="btn btn-text" disabled={checking} onClick={checkForBreaches}>
            {checking ? "Checking…" : "Check again"}
          </button>
        )}
      </div>
      <p className="card-text">Attackers try passwords from known breaches first, on every site. Change these even if they look strong.</p>

      {availability === "off" || availability === "unknown" ? (
        <p className="small muted">
          {availability === "off"
            ? "This server doesn't allow checking passwords against Have I Been Pwned."
            : "Couldn't load your server's settings, so the breach check isn't available right now. Reload the page to try again."}
        </p>
      ) : (
        <p className="privacy-note small">
          <Icon name="shield" size={16} />
          <span>The first 5 characters of each password's SHA-1 hash go to Have I Been Pwned; your passwords never leave this device.</span>
        </p>
      )}

      {allowed && !results && (
        <div className="card-actions">
          <button type="button" className="btn btn-primary" disabled={checking} onClick={checkForBreaches}>
            <Icon name="shield" /> {checking ? "Checking…" : status === "failed" ? "Try again" : "Check for exposed passwords"}
          </button>
        </div>
      )}

      {checking && (
        <div className="stack-s">
          <div className="progress" role="progressbar" aria-label="Breach check" aria-valuemin={0} aria-valuemax={100} aria-valuenow={pct}>
            <i style={{ width: `${pct}%` }} />
          </div>
          <p className="small muted" aria-hidden="true">
            {check.total ? `Checked ${fmt(check.done)} of ${count(check.total, "password", "passwords")}` : "Starting…"}
          </p>
        </div>
      )}
      <p className="sr-only" role="status">
        {announcement}
      </p>

      {status === "failed" && check.error && (
        <div className="alert alert-error" role="alert">
          {check.error}
        </div>
      )}

      {results &&
        (exposed.length > 0 ? (
          <LoginRows entries={exposed} labelledBy="health-exposed" trail={(e) => timesSeen(results.get(passwordOf(e)) ?? 0)} />
        ) : unchecked < total ? (
          <AllClear title="No exposed passwords found" text="None of the checked passwords appear in known data breaches." />
        ) : null)}

      {results && (
        <p className="small muted">
          {check.checkedAt && `Last checked at ${new Date(check.checkedAt).toLocaleTimeString(undefined, { timeStyle: "short" })}. `}
          {unchecked > 0 && `${count(unchecked, "login was", "logins were")} added or changed since then; check again to include them.`}
        </p>
      )}
    </section>
  );
}

const timesSeen = (n: number) => `Seen ${count(n, "time", "times")}`;

function AllClear({ title, text }: { title: string; text: string }) {
  return (
    <div className="health-clear">
      <span className="tile tile-ok" aria-hidden="true">
        <Icon name="check" />
      </span>
      <span className="grow">
        <span className="row-title">{title}</span>
        <span className="row-sub">{text}</span>
      </span>
    </div>
  );
}

function LoginRows({ entries, labelledBy, trail }: { entries: VaultEntry[]; labelledBy: string; trail?: (e: VaultEntry) => ReactNode }) {
  const { vaults } = useVault();
  const showIcons = useSiteIconsShown();
  return (
    <div className="choices health-rows" role="group" aria-labelledby={labelledBy}>
      {entries.map((e) => (
        <LoginRow key={e.id} entry={e} vault={vaults.find((v) => v.id === e.vaultId)} showIcons={showIcons} trail={trail?.(e)} />
      ))}
    </div>
  );
}

/** One login: name, user name and site, its vault (shared vaults marked); opens the item to change the password. */
function LoginRow({ entry, vault, showIcons, trail }: { entry: VaultEntry; vault?: Vault; showIcons: boolean; trail?: ReactNode }) {
  const i = entry.item;
  const host = siteHost(i);
  const canEdit = !!vault && vault.role !== "read";
  const shared = vault?.kind === "sealed";
  const details = [i.login?.username, host].filter(Boolean).join(" · ");
  const state: HealthLinkState = { from: "/health", edit: canEdit };
  return (
    <Link className="choice" to={`${filterPath("all")}/${entry.id}`} state={state}>
      <SiteIcon host={host} name={i.name} enabled={showIcons} />
      <span className="choice-text">
        <span className="choice-title">{i.name || "Untitled"}</span>
        {details && <span className="choice-sub">{details}</span>}
        <span className="choice-sub health-vault">
          {shared && <Icon name="share" size={12} />}
          <span>
            {vault?.name ?? "Vault"}
            {shared && " (shared)"}
            {!canEdit && ", view only"}
          </span>
        </span>
      </span>
      {trail && <span className="choice-trail">{trail}</span>}
      <span className="choice-trail" aria-hidden="true">
        <Icon name="chevron" size={16} />
      </span>
    </Link>
  );
}
