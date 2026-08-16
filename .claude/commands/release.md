Perform a release of cfirewalld.

Optional override: $ARGUMENTS (format: vX.Y.Z). If provided, use that version.

## Version determination

1. Find the last release tag (`git tag --sort=-v:refname | head -1`). Tags are
   named `cfirewalld-vX.Y.Z`.
2. Examine commits since that tag to classify the release type:
   - **Patch**: only bug fixes, dependency bumps, build changes, docs.
   - **Minor**: new features (`feat:`), new subcommands or config surface.
   - **Major**: incompatible config changes, a removed `firewall.d` construct,
     anything that makes an existing config stop loading.
3. Bump the version accordingly. If **major**, stop and confirm before proceeding.

## Pre-release checks

The `pre-commit` hook runs fmt, clippy and the unit tests, so the release commit
is already gated by it. What the hook does not cover:

```sh
./tests/check-shell-syntax.sh
./build-helper.sh x86_64
./tests/integration.sh
```

Integration tests need `NET_ADMIN` and `NET_RAW`; `./tests/check-netfilter.sh`
answers whether this machine grants both.

## Steps

1. Bump `version` in `Cargo.toml`.

2. Run the pre-release checks above.

3. Draft a changelog from `git log --oneline <last-tag>..HEAD`.

   **Rules:**
   - Group under: `New features:`, `Bug fixes:`, `Build:`, `Refactoring:` — omit empty sections.
   - Describe user-visible behavior, not implementation details.
   - Merge related commits for the same feature into one bullet.
   - No git hashes, no raw commit subjects, no co-author lines.

4. Commit the bump and build the tag locally — nothing is pushed yet. The tag
   sits on a detached child commit that pins `Cargo.lock`, so the lock never
   lands on master while the released packages still build from an exact
   dependency set:

```sh
git add Cargo.toml
git commit -m "release: vX.Y.Z"
git checkout --detach
git add -f Cargo.lock
git commit -m "build: pin Cargo.lock for vX.Y.Z"
git tag -as cfirewalld-vX.Y.Z -F <changelog-file>
git switch master
```

   Run these as **separate** commands, never chained with `&&`. If a chained
   command is rejected part-way — a hook, a denied permission — the untried
   half is silently skipped, and the failure mode here is committing
   `Cargo.lock` onto master because the `git checkout --detach` never ran.
   After `git checkout --detach`, confirm with `git symbolic-ref -q HEAD`
   (it must fail) before staging the lock.

   If `Cargo.toml` already carries the target version, the bump commit is empty —
   skip it rather than passing `--allow-empty`.

5. Push master, wait for CI green:

```sh
git push
gh run watch "$(gh run list --workflow=ci.yml -b master -L1 --json databaseId --jq '.[0].databaseId')" --exit-status
```

   No run within a couple of minutes: check the `Actions` component at
   `https://www.githubstatus.com/api/v2/components.json` — during an outage no
   run is created and missed events are never backfilled. Stop and report.

   Red: fix on master, rebuild the tag onto the new head, restart this step.

6. Push the tag:

```sh
git push origin cfirewalld-vX.Y.Z
```

7. **Build the packages from the tagged commit, not from master:**

```sh
git checkout cfirewalld-vX.Y.Z
make deb-all
```

   The Makefile stamps a plain `X.Y.Z` only when `git describe --exact-match`
   names a `cfirewalld-v*` tag on a clean tree; anywhere else it appends a
   `+<count>.<timestamp>-<sha>` build suffix. aptly takes the release version,
   so building from master produces packages it will not accept. `Cargo.lock` is
   tracked on the tag, which is also what lets `make` find the prerequisite it
   requires.

   Confirm before uploading:

```sh
dpkg-deb -f cfirewalld_X.Y.Z_amd64.deb Version Architecture
dpkg-deb -f cfirewalld_X.Y.Z_arm64.deb Version Architecture
```

8. Deploy, then return to master:

```sh
./deploy-aptly.sh
git switch master
```

   `deploy-aptly.sh` globs every `./*.deb`, so remove or move aside any leftover
   development builds first — the repo keeps only the newest few versions per
   architecture, and stale uploads evict the release. `git switch master`
   deletes the working-tree `Cargo.lock` (untracked there).

9. Report the tag, the changelog, the CI run that gated the release, and the
   package versions deployed.

## Important

- **Never release a commit CI has not run on.** If the tree changed after the
  checks — a rebase, a hand-resolved conflict, a dependency that resolved
  differently — the earlier green run does not cover it. Re-run the checks and
  go back to step 5.
- **Ask before deploying when anything deviated from these steps.** An outage, a
  rebase, a skipped step, a red-then-fixed run: report the state and let me decide.
- **Cargo.lock never reaches master** — it stays gitignored there and exists only
  on the tag's own commit, so a release build is reproducible.
- The tag is IMMUTABLE once pushed — never retag. Wrong? Make a new patch release.
