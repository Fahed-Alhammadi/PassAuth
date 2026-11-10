# Vendored crates

## sqlx-sqlite 0.9.0

The published `sqlx-sqlite` 0.9.0 crate (checksum `488e99c3…2e982c`, same as
the crates.io release) with one change: the `libsqlite3-sys` version range in
`Cargo.toml` is `>=0.30.1, <0.40.0` instead of `<0.38.0`. This lets the server
build against `libsqlite3-sys` 0.39, which bundles SQLite 3.54 and fixes
RUSTSEC-2026-0459. Upstream made the same change on main (launchbadge/sqlx#4402,
#4502) but has not released it yet (launchbadge/sqlx#4516).

Remove this folder and the `[patch.crates-io]` entry in the root `Cargo.toml`
once a sqlx release allows `libsqlite3-sys` 0.39, then run
`cargo update -p sqlx`.
