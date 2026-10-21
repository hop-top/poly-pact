# PHP dependencies

This file registers third-party Composer packages for the PACT protocol's PHP SDK (`php/`). A package reaches `composer.json` only after a vet with `rsx` in deep mode (`rsx analyze <repo> --mode deep`) passes the balanced policy check (`rsx policy test <repo> --policy-profile balanced`). A failure is recorded here instead of a pin. Each row captures what `rsx` reported plus separately verified facts: Packagist metadata, the `LICENSE` file and `composer.json` at the tag, the GitHub API, and the Packagist security-advisory feed. The `require` lines are in `php/composer.json`, the exact versions in `php/composer.lock`. Rows are appended as packages are vetted; existing rows are only edited to correct them or record a re-vet.

The candidates come from the primitive probes run before the vet. The probe chose the builtin extensions (`ext-openssl`, `ext-json`, `ext-mbstring`, `ext-pcre`) and in-house code for ES256 signature conversion, JWK handling, JWK thumbprints, strict JSON scanning and JCS. Only JSON Schema validation is a Composer dependency. The probe did not choose a test runner, a static analyser or a code-style tool, so those are vetted here as candidates.

- **Package** – the Packagist name, then the GitHub slug that was run through `rsx` (confirmed from the `repository` field in the Packagist metadata, not guessed from the vendor name)
- **Used by** – the part of the SDK that imports it, or the development task that runs it
- **Version to pin** – the exact version to put in `composer.json`
- **License** – the SPDX license identifier
- **Maintenance** – `rsx` maintenance signals and separately verified facts, including the date of the latest release
- **rsx verdict** – the `rsx` result under the balanced policy, with the date of the vet
- **Constraint** – where the package may or may not be used; `none` when there is no constraint

How to read the `rsx` numbers: `rsx` scores a repository, not a release line, so one verdict covers every version of a package. Its adoption (`dependents`), active-maintainer, bus-factor, last-maintainer-activity and signed-release values are proxies by its own evidence notes (for example, `dependents` is a stars/20 estimate), so they are not cited below; release and commit dates come from Packagist and the GitHub API instead. Every run was made on 2026-10-16, except the re-vets dated 2026-10-20 that followed the raise of the PHP floor to 8.4.

## Vetted dependencies

### Runtime

| Package | Used by | Version to pin | License | Maintenance | rsx verdict | Constraint |
| --- | --- | --- | --- | --- | --- | --- |
| Packagist `opis/json-schema`<br>GitHub `opis/json-schema` | JSON Schema 2020-12 validation of the published PACT schema | `2.6.0` (PHP `^7.4 \|\| ^8.0`; requires `ext-json`, `opis/string` `^2.1`, `opis/uri` `^1.0`) | Apache-2.0 (Packagist; `LICENSE` and `composer.json` at tag `2.6.0` verified) | rsx: maintenance 6.0/10, activity 1.2/10, release hygiene 8.0/10, community 5.4/10, docs 5.0/10; Scorecard Maintained 0/10 (no commits or issue activity in the 90 days before the run), Code-Review 4/10, Branch-Protection 0/10.<br>Latest release `2.6.0`, 2025-10-17 (Packagist and GitHub release). Last commit on `master` 2026-04-30 (unreleased, after `2.6.0`; GitHub API). Not archived. Packagist also lists `1.3.0` (2025-11-19) on the separate 1.x line; not used.<br>Packagist security advisories: none. | PASS, balanced, deep; score 5.7/10; 2026-10-16 | Schema validation only. Never used to parse JSON, canonicalize, or handle signatures; the SDK does those itself (probe decision table). Feed it `stdClass` objects, because associative arrays fail `type`. The SDK adds its own trailing-newline check for anchored patterns and `format: "uri"`. Pin the exact version; the weak activity signal is the reason to re-vet on any bump. |
| Packagist `opis/string`<br>GitHub `opis/string` | Required by `opis/json-schema` (transitive); no direct import | `2.1.0` (via `composer.lock`; PHP `^7.4 \|\| ^8.0`; requires `ext-json`, `ext-iconv`) | Apache-2.0 (Packagist; `LICENSE` and `composer.json` at tag `2.1.0` verified) | rsx: maintenance 6.0/10, activity 1.0/10, release hygiene 10.0/10, community 3.4/10, docs 6.5/10; Scorecard Maintained 0/10, Code-Review 1/10, Security-Policy 0/10.<br>Latest release `2.1.0`, 2025-10-17; last commit on `master` the same day (GitHub API). Not archived.<br>Packagist security advisories: none. | PASS, balanced, deep; score 5.5/10; 2026-10-16 | Transitive only. Adds the `ext-iconv` platform requirement. |
| Packagist `opis/uri`<br>GitHub `opis/uri` | Required by `opis/json-schema` (transitive); no direct import | `1.1.0` (via `composer.lock`; PHP `^7.4 \|\| ^8.0`; requires `opis/string` `^2.0`) | Apache-2.0 (Packagist; `LICENSE` and `composer.json` at tag `1.1.0` verified) | rsx: maintenance 6.0/10, activity 1.0/10, release hygiene 6.0/10, community 2.2/10, docs 3.0/10, adoption 0.0/10; the lowest score of the set. Scorecard Maintained 0/10, Code-Review 0/10, Security-Policy 0/10; 2 contributors.<br>Latest release `1.1.0`, 2021-05-22 (Packagist and GitHub release); no release in more than 5 years. Last commit on `master` 2025-11-19, "Added php 8.5 to tests" (GitHub API; `rsx` reports 2024-12-30 because it uses the last merged pull request as a stand-in). Not archived.<br>Packagist security advisories: none. | PASS, balanced, deep; score 4.7/10; 2026-10-16 | Transitive only. It is the weakest link of the runtime set: if a later re-vet fails the balanced policy, the options are the probe's in-house evaluator or the runner-up under "Rejected", not an unvetted pin. |

### Development

| Package | Used by | Version to pin | License | Maintenance | rsx verdict | Constraint |
| --- | --- | --- | --- | --- | --- | --- |
| Packagist `phpunit/phpunit`<br>GitHub `sebastianbergmann/phpunit` | Test runner (`require-dev`) | `13.4.1` (PHP `>=8.4.1`), for the PHP floor of 8.4. `13.4.2` (2026-10-12) and `13.4.3` (2026-10-16) are newer but younger than 14 days on 2026-10-20 and carry no security fix (ChangeLog-13.4.md: bug fixes only), so they are not taken. `12.5.40` (PHP `>=8.3`) was the pin for the former 8.3 floor. | BSD-3-Clause (Packagist; `LICENSE` and `composer.json` at tag `13.4.1` verified) | rsx: maintenance 9.0/10, activity 8.1/10, release hygiene 8.0/10, community 9.0/10, docs 7.0/10, security 4.6/10. The security score fell from 7.8/10 (2026-10-16) because `rsx` now counts 2 high-severity vulnerabilities against the repository; they are the two CVEs below, neither of which affects `13.4.1`.<br>Releases: `13.4.1` 2026-10-05, `13.4.2` 2026-10-12, `13.4.3` 2026-10-16 (Packagist).<br>Support policy (phpunit.de, fetched 2026-10-20): PHPUnit 13 (PHP >= 8.4) has bugfix support until 2028-02-04; PHPUnit 12 (PHP >= 8.3) until 2027-02-05.<br>Packagist security advisories: CVE-2026-24765 (affects 11.x before `11.5.50` and 12.x before `12.5.8`, among other lines) and CVE-2026-41570 (affects `>=12.5.21,<12.5.22` and `>=13.1.5,<13.1.6`); `13.4.1` is in neither range, and `composer audit` reports no advisory for the lock. CVE-2017-9841 affects only 4.x and 5.x. | PASS, balanced, deep; score 7.1/10; 2026-10-20 (7.9/10 on 2026-10-16) | Development only; never in `require`. Needs `ext-dom`, `ext-filter`, `ext-json`, `ext-libxml`, `ext-mbstring`, `ext-xmlwriter`: present on PHP 8.5.11 (section "Platform extensions"); `ci-php` installs them on 8.4 and 8.5. |
| Packagist `phpstan/phpstan`<br>GitHub `phpstan/phpstan` | Static analysis (`require-dev`) | `2.3.1` (PHP `^7.4 \|\| ^8.0`; no other requirement) | MIT (Packagist; `LICENSE` and `composer.json` at tag `2.3.1` verified) | rsx: maintenance 10.0/10, activity 5.8/10, release hygiene 10.0/10, community 9.0/10, docs 6.5/10, security 9.5/10; Scorecard Signed-Releases 8/10, SAST 10/10, Code-Review 1/10.<br>Latest release `2.3.1`, 2026-10-08 (Packagist and GitHub release). The repository pushed 2026-10-16. 1169 open issues and pull requests (GitHub API), a large backlog.<br>Packagist lists `phpstan/phpstan-src` as the source repository; `phpstan/phpstan` is the distribution repository (Packagist `bin`: `phpstan`, `phpstan.phar`). `phpstan/phpstan-src` also passes: PASS, balanced, deep; score 6.8/10 (release hygiene 2.0/10 because releases are published from the distribution repository).<br>Packagist security advisories: none. | PASS, balanced, deep; score 8.1/10; 2026-10-16 | Development only. Runs on PHP 8.5.11 (`make php-lint`); `ci-php` runs it on 8.4 and 8.5. |
| Packagist `friendsofphp/php-cs-fixer`<br>GitHub `PHP-CS-Fixer/PHP-CS-Fixer` | Code-style checker and fixer (`require-dev`, or a separate tools directory) | `3.95.27` (tag `v3.95.27`; PHP `^7.4 \|\| ^8.0`) | MIT (Packagist; `LICENSE` text and `composer.json` at tag `v3.95.27` verified) | rsx: maintenance 10.0/10, activity 6.3/10, release hygiene 10.0/10, community 8.0/10, docs 8.5/10, security 9.6/10; Scorecard Signed-Releases 8/10, Branch-Protection 8/10, Dependency-Update-Tool 10/10, Code-Review 4/10.<br>Latest release `v3.95.27`, 2026-09-22 (Packagist and GitHub release). The repository pushed 2026-10-09.<br>Packagist security advisories: none. | PASS, balanced, deep; score 8.3/10; 2026-10-16 | Development only. Brings a sizeable transitive tree (`symfony/*`, `react/*`, `composer/*`, `sebastian/diff`, `fidry/cpu-core-counter`, `clue/ndjson-react`, `ergebnis/agent-detector`; Packagist `require`), vetted under "Package audit". Runs on PHP 8.5.11 (`make php-lint`); `ci-php` runs it on 8.4 and 8.5. |

## Comparisons

`rsx compare --mode deep`, 2026-10-16:

| Pair | Result | Decision |
| --- | --- | --- |
| `jsonrainbow/json-schema` against `opis/json-schema` | Overall 7.8 against 5.7; security 8.7 against 7.8; activity 4.0 against 1.2; maintenance 10.0 against 6.0; license 10.0 for both. Both PASS the balanced policy. | `opis/json-schema` stays. The policy did not block it, and the probe selected it on function, not on repository health: it validates the schema as published, offline, with 36 of 36 vectors agreeing, while `justinrainbow/json-schema` throws on the `urn:uuid:` `$id` and is documented to Draft 2019-09. A higher health score does not repair that. |
| `PHP-CS-Fixer/PHP-CS-Fixer` against `laravel/pint` | Overall 8.3 against 7.7; security 9.6 against 9.3; activity 6.3 against 2.9; maintenance 10.0 for both; license 10.0 for both. Both PASS the balanced policy. | `friendsofphp/php-cs-fixer`. It scores higher, and `laravel/pint` `v1.32.1` requires PHP `^8.3.0` (Packagist), so it cannot be installed on the 8.2 floor. |

## Rejected

| Package | Verdict | Why |
| --- | --- | --- |
| `justinrainbow/json-schema` (GitHub `jsonrainbow/json-schema`; `6.13.1`, MIT, 2026-09-30) | rsx PASS, balanced, deep; score 7.8/10; 2026-10-16. License verified at tag `6.13.1`. | Rejected by the probe on function: cannot resolve the schema as published (`urn:uuid:` `$id`), documented to 2019-09 and not 2020-12, rejects `2.0` as a non-integer, weaker `format: "uri"`, accepts a newline after `$`. It would also add `marc-mabe/php-enum` (not vetted here). Usable only on a modified copy of the schema, so it is a fallback only after a design decision. |
| `laravel/pint` (GitHub `laravel/pint`; `v1.32.1`, MIT, 2026-09-10) | rsx PASS, balanced, deep; score 7.7/10; 2026-10-16. License verified at tag `v1.32.1`. | Requires PHP `^8.3.0`, which the 8.4 floor meets, but scores below `friendsofphp/php-cs-fixer` (see Comparisons). Reconsider only if there is a reason to prefer it. |

Rejected by the probe on function and not run through `rsx`, because no policy result can reinstate them:

| Package | Why not |
| --- | --- |
| `firebase/php-jwt`, `phpseclib/phpseclib` (with `paragonie/constant_time_encoding` and `paragonie/random_compat`) | No DER or JOSE helper is needed: the probe kept the in-house converter. Both accept non-canonical signatures; `firebase/php-jwt` also accepts unknown `crit` and any `typ`; `phpseclib` is about 3.5 times slower than `ext-openssl`. |
| `seld/jsonlint` | Clamps big integers and accepts invalid UTF-8 and lone surrogates. |
| `root23/php-json-canonicalization`, `mmccook/php-json-canonicalization-scheme`, `truschery/kanon` | Wrong number text: 9941, 9941 and 113 of 10000. |
| `lcobucci/jwt`, `web-token/jwt-library`, `swaggest/json-schema` | Not probed further: the first two were only read from `composer show -a` (`lcobucci/jwt` requires PHP `~8.4.0 \|\| ~8.5.0`, so it cannot run on 8.2), and the last was not run. |

## Package audit

`php/composer.lock` resolves 68 packages under `config.platform.php` `8.4.1`: 3 runtime (`packages`) and 65 development (`packages-dev`). All runs below were made on 2026-10-20 (`rsx` vdev, Composer 2.10.3, PHP 8.5.11).

`rsx audit php/ --mode deep --policy-profile balanced` reads the lock file and exits 0: manifests 1 (`composer.lock`), dependencies 65, unresolved 65. It maps no Packagist name to a repository and so gives no analysis and no policy result. The six packages with rows above are covered by those rows (vetted 2026-10-16, not re-run). Every other package of the lock was run one by one (the packages that changed with the 8.4 floor again on 2026-10-20, after the lock moved), by the GitHub slug taken from the `source.url` of its lock entry: `rsx analyze <repo> --mode deep`, then `rsx policy test <repo> --policy-profile balanced`. `phpstan/phpstan` has no `source` entry in the lock (dist only); its row above covers it.

`composer audit` (run from `php/`): "No security vulnerability advisories found", exit 0.

### Transitive packages

All development only: none is reached from `opis/json-schema`, so none ships with the runtime set. "Required by" lists the packages of the lock that require it. License is the lock's `license` field.

| Package | Version | License | Required by | rsx verdict (balanced, deep, 2026-10-20) |
| --- | --- | --- | --- | --- |
| `clue/ndjson-react` (GitHub `clue/reactphp-ndjson`) | `v1.3.0` | MIT | `friendsofphp/php-cs-fixer` | PASS 5.8/10 |
| `composer/pcre` | `3.4.0` | MIT | `composer/xdebug-handler` | PASS 4.9/10 |
| `composer/semver` | `3.5.1` | MIT | `friendsofphp/php-cs-fixer` | PASS 6.7/10 |
| `composer/xdebug-handler` | `3.0.5` | MIT | `friendsofphp/php-cs-fixer` | PASS 4.3/10 |
| `ergebnis/agent-detector` | `1.3.0` | MIT | `friendsofphp/php-cs-fixer` | PASS 7.3/10 |
| `evenement/evenement` (GitHub `igorw/evenement`) | `v3.0.2` | MIT | `react/child-process`, `react/socket`, `react/stream` | PASS 4.9/10 |
| `fidry/cpu-core-counter` (GitHub `theofidry/cpu-core-counter`) | `1.4.1` | MIT | `friendsofphp/php-cs-fixer` | PASS 6.5/10 |
| `myclabs/deep-copy` (GitHub `myclabs/DeepCopy`) | `1.14.0` | MIT | `phpunit/phpunit` | PASS 6.3/10 |
| `nikic/php-parser` (GitHub `nikic/PHP-Parser`) | `v5.9.0` | BSD-3-Clause | `phpunit/php-code-coverage`, `sebastian/complexity`, `sebastian/lines-of-code` | PASS 7.4/10 |
| `phar-io/manifest` | `2.0.4` | BSD-3-Clause | `phpunit/phpunit` | PASS 5.0/10 |
| `phar-io/version` | `3.2.1` | BSD-3-Clause | `phar-io/manifest`, `phpunit/phpunit` | PASS 5.9/10 |
| `phpunit/php-code-coverage` (GitHub `sebastianbergmann/php-code-coverage`) | `14.4.1` | BSD-3-Clause | `phpunit/phpunit` | PASS 6.7/10 |
| `phpunit/php-file-iterator` (GitHub `sebastianbergmann/php-file-iterator`) | `7.0.2` | BSD-3-Clause | `phpunit/phpunit` | PASS 6.3/10 |
| `phpunit/php-invoker` (GitHub `sebastianbergmann/php-invoker`) | `7.0.0` | BSD-3-Clause | `phpunit/phpunit` | PASS 5.7/10 |
| `phpunit/php-text-template` (GitHub `sebastianbergmann/php-text-template`) | `6.0.1` | BSD-3-Clause | `phpunit/php-code-coverage`, `phpunit/phpunit` | PASS 6.2/10 |
| `phpunit/php-timer` (GitHub `sebastianbergmann/php-timer`) | `9.0.0` | BSD-3-Clause | `phpunit/phpunit` | PASS 6.0/10 |
| `psr/container` (GitHub `php-fig/container`) | `2.0.2` | MIT | `symfony/service-contracts` | PASS 5.4/10 |
| `psr/event-dispatcher` (GitHub `php-fig/event-dispatcher`) | `1.0.0` | MIT | `symfony/event-dispatcher-contracts` | PASS 5.0/10 |
| `psr/log` (GitHub `php-fig/log`) | `3.0.2` | MIT | `composer/xdebug-handler` | PASS 5.8/10 |
| `react/cache` (GitHub `reactphp/cache`) | `v1.2.0` | MIT | `react/dns` | PASS 5.5/10 |
| `react/child-process` (GitHub `reactphp/child-process`) | `v0.6.7` | MIT | `friendsofphp/php-cs-fixer` | PASS 5.9/10 |
| `react/dns` (GitHub `reactphp/dns`) | `v1.14.0` | MIT | `react/socket` | PASS 6.3/10 |
| `react/event-loop` (GitHub `reactphp/event-loop`) | `v1.6.0` | MIT | `friendsofphp/php-cs-fixer`, `react/child-process`, `react/dns`, `react/socket`, `react/stream` | PASS 6.2/10 |
| `react/promise` (GitHub `reactphp/promise`) | `v3.3.0` | MIT | `react/cache`, `react/dns`, `react/socket` | PASS 5.7/10 |
| `react/socket` (GitHub `reactphp/socket`) | `v1.17.0` | MIT | `friendsofphp/php-cs-fixer` | PASS 6.4/10 |
| `react/stream` (GitHub `reactphp/stream`) | `v1.4.0` | MIT | `clue/ndjson-react`, `friendsofphp/php-cs-fixer`, `react/child-process`, `react/socket` | PASS 5.9/10 |
| `sebastian/cli-parser` (GitHub `sebastianbergmann/cli-parser`) | `5.0.1` | BSD-3-Clause | `phpunit/phpunit` | PASS 5.9/10 |
| `sebastian/comparator` (GitHub `sebastianbergmann/comparator`) | `8.4.0` | BSD-3-Clause | `phpunit/phpunit` | PASS 6.0/10 |
| `sebastian/complexity` (GitHub `sebastianbergmann/complexity`) | `6.0.0` | BSD-3-Clause | `phpunit/php-code-coverage` | PASS 6.9/10 |
| `sebastian/diff` (GitHub `sebastianbergmann/diff`) | `9.0.1` | BSD-3-Clause | `friendsofphp/php-cs-fixer`, `phpunit/phpunit`, `sebastian/comparator` | PASS 7.0/10 |
| `sebastian/environment` (GitHub `sebastianbergmann/environment`) | `9.3.3` | BSD-3-Clause | `phpunit/php-code-coverage`, `phpunit/phpunit` | PASS 7.1/10 |
| `sebastian/exporter` (GitHub `sebastianbergmann/exporter`) | `8.2.1` | BSD-3-Clause | `phpunit/phpunit`, `sebastian/comparator` | PASS 7.1/10 |
| `sebastian/file-filter` (GitHub `sebastianbergmann/file-filter`) | `1.0.0` | BSD-3-Clause | `phpunit/phpunit` | PASS 6.3/10 |
| `sebastian/git-state` (GitHub `sebastianbergmann/git-state`) | `1.0.0` | BSD-3-Clause | `phpunit/php-code-coverage`, `phpunit/phpunit` | PASS 5.5/10 |
| `sebastian/global-state` (GitHub `sebastianbergmann/global-state`) | `9.0.1` | BSD-3-Clause | `phpunit/phpunit` | PASS 7.0/10 |
| `sebastian/lines-of-code` (GitHub `sebastianbergmann/lines-of-code`) | `5.0.2` | BSD-3-Clause | `phpunit/php-code-coverage` | PASS 6.7/10 |
| `sebastian/object-enumerator` (GitHub `sebastianbergmann/object-enumerator`) | `8.1.0` | BSD-3-Clause | `phpunit/phpunit` | PASS 7.0/10 |
| `sebastian/object-reflector` (GitHub `sebastianbergmann/object-reflector`) | `6.1.0` | BSD-3-Clause | `sebastian/global-state` | PASS 7.0/10 |
| `sebastian/recursion-context` (GitHub `sebastianbergmann/recursion-context`) | `8.0.1` | BSD-3-Clause | `phpunit/phpunit`, `sebastian/exporter`, `sebastian/global-state`, `sebastian/object-enumerator` | PASS 6.9/10 |
| `sebastian/type` (GitHub `sebastianbergmann/type`) | `7.0.2` | BSD-3-Clause | `phpunit/phpunit` | PASS 6.8/10 |
| `sebastian/version` (GitHub `sebastianbergmann/version`) | `7.0.1` | BSD-3-Clause | `phpunit/php-code-coverage`, `phpunit/phpunit` | PASS 6.9/10 |
| `staabm/side-effects-detector` | `1.0.5` | MIT | `phpunit/phpunit` | PASS 5.1/10 |
| `symfony/console` | `v8.1.8` | MIT | `friendsofphp/php-cs-fixer` | PASS 6.6/10 |
| `symfony/deprecation-contracts` | `v3.7.1` | MIT | `symfony/console`, `symfony/event-dispatcher`, `symfony/filesystem`, `symfony/options-resolver`, `symfony/service-contracts` | PASS 5.9/10 |
| `symfony/event-dispatcher` | `v8.1.5` | MIT | `friendsofphp/php-cs-fixer` | PASS 6.6/10 |
| `symfony/event-dispatcher-contracts` | `v3.7.1` | MIT | `symfony/event-dispatcher` | PASS 6.0/10 |
| `symfony/filesystem` | `v8.1.9` | MIT | `friendsofphp/php-cs-fixer` | PASS 6.4/10 |
| `symfony/finder` | `v8.1.8` | MIT | `friendsofphp/php-cs-fixer` | PASS 6.6/10 |
| `symfony/options-resolver` | `v8.1.0` | MIT | `friendsofphp/php-cs-fixer` | PASS 6.3/10 |
| `symfony/polyfill-ctype` | `v1.37.0` | MIT | `symfony/filesystem`, `symfony/string` | PASS 5.5/10 |
| `symfony/polyfill-intl-grapheme` | `v1.43.0` | MIT | `symfony/string` | PASS 5.9/10 |
| `symfony/polyfill-intl-normalizer` | `v1.43.0` | MIT | `symfony/string` | PASS 5.7/10 |
| `symfony/polyfill-mbstring` | `v1.43.0` | MIT | `friendsofphp/php-cs-fixer`, `symfony/console`, `symfony/filesystem`, `symfony/string` | PASS 6.2/10 |
| `symfony/polyfill-php80` | `v1.43.0` | MIT | `friendsofphp/php-cs-fixer` | PASS 5.7/10 |
| `symfony/polyfill-php81` | `v1.38.1` | MIT | `friendsofphp/php-cs-fixer` | PASS 5.6/10 |
| `symfony/polyfill-php84` | `v1.43.0` | MIT | `friendsofphp/php-cs-fixer` | PASS 5.7/10 |
| `symfony/polyfill-php85` | `v1.43.0` | MIT | `symfony/console` | PASS 5.7/10 |
| `symfony/process` | `v8.1.7` | MIT | `friendsofphp/php-cs-fixer` | PASS 6.5/10 |
| `symfony/service-contracts` | `v3.7.3` | MIT | `symfony/console`, `symfony/stopwatch` | PASS 6.1/10 |
| `symfony/stopwatch` | `v8.1.0` | MIT | `friendsofphp/php-cs-fixer` | PASS 6.3/10 |
| `symfony/string` | `v8.1.9` | MIT | `symfony/console` | PASS 6.3/10 |
| `theseer/tokenizer` | `2.0.1` | BSD-3-Clause | `phpunit/php-code-coverage` | PASS 4.8/10 |

Notes on the results:

- No package fails the balanced policy. The lowest scores are `composer/xdebug-handler` 4.3/10, `theseer/tokenizer` 4.8/10, `composer/pcre` 4.9/10 and `evenement/evenement` 4.9/10.
- `symfony/string` and `theseer/tokenizer` first returned a cached quick-mode result (5.7/10 and 4.2/10); they were re-run with `--refresh` in deep mode, and the table gives the deep scores.
- `theseer/tokenizer` and `phar-io/manifest` score 3.0/10 on license in `rsx`: the GitHub API reports `NOASSERTION` for both, because each `LICENSE` file opens with a project-name header before the BSD 3-clause text. The lock declares BSD-3-Clause for both, and the `LICENSE` text (GitHub API) is the BSD 3-clause license.

### Platform extensions

`composer check-platform-reqs` (from `php/`, PHP 8.5.11) passes for every requirement of the lock: `php`, `ext-dom`, `ext-filter`, `ext-hash`, `ext-iconv`, `ext-json`, `ext-libxml`, `ext-mbstring`, `ext-openssl`, `ext-pcre`, `ext-phar`, `ext-tokenizer` and `ext-xmlwriter`. With `--no-dev` the list is `php`, `ext-hash`, `ext-iconv`, `ext-json`, `ext-mbstring`, `ext-openssl` and `ext-pcre`.

- Runtime set: `ext-hash`, `ext-json`, `ext-mbstring`, `ext-openssl`, `ext-pcre` (from `php/composer.json`) and `ext-iconv` (from `opis/string`).
- Development set adds `ext-dom` (`phpunit/phpunit`, `phpunit/php-code-coverage`, `sebastian/comparator`, `phar-io/manifest`, `theseer/tokenizer`), `ext-libxml` (`phpunit/phpunit`, `phpunit/php-code-coverage`, `phar-io/manifest`), `ext-xmlwriter` (`phpunit/phpunit`, `phpunit/php-code-coverage`, `phar-io/manifest`, `theseer/tokenizer`), `ext-filter` (`phpunit/phpunit`, `friendsofphp/php-cs-fixer`), `ext-tokenizer` (`friendsofphp/php-cs-fixer`, `nikic/php-parser`, `staabm/side-effects-detector`, `theseer/tokenizer`) and `ext-phar` (`phar-io/manifest`).
- `ext-mbstring`: Composer reports it as "provided by symfony/polyfill-mbstring", because the polyfill declares it in `provide`. The polyfill enters only through the development set (`friendsofphp/php-cs-fixer`, `symfony/console`, `symfony/filesystem`, `symfony/string`), so a `--no-dev` install has no polyfill and the runtime set needs the extension itself; `php/composer.json` requires it. The local PHP 8.5.11 loads `mbstring` natively (`php -m`).

## CI and re-vets

- PHP versions: the floor is 8.4: `php` `>=8.4` in `require`, `config.platform.php` `8.4.1`. It was 8.3 until 2026-10-20, when it was raised to take PHPUnit 13 and Symfony 8. `config.platform.php` is `8.4.1` rather than `8.4.0` because `phpunit/phpunit` 13 and the `symfony/*` 8 packages require PHP `>=8.4.1`; the runtime set alone installs on any 8.4. Only PHP 8.5.11 is installed on the machine that made this record, so nothing here ran on 8.4 locally. `ci-php` runs `phpunit`, `phpstan` and `php-cs-fixer` on 8.4 and 8.5 (setup-php), and `composer check-platform-reqs --no-dev` on both.
- `rsx audit php/` resolves no Packagist name to a repository (section "Package audit"), so the transitive packages are vetted one by one there.
- Any package here is re-vetted when its pinned or locked version changes.
- Guard: `php/tests/Deps/DepcheckTest.php` (run by `make php-test`) fails when `php/composer.json`, `php/composer.lock` or the PHP sources leave the vetted sets of `php/tests/testdata/deps-vetted.json`, or when this record does not list the same packages and versions. It checks: `require` and `require-dev` are exactly the vetted exact pins, each pin is the locked version; the `php` constraint and `config.platform` are the floor above; the `ext-*` set is the runtime set of "Platform extensions"; no `repositories`, no plugins; each lock section holds exactly the vetted packages at the vetted versions, from GitHub, none a plugin; the Runtime table lists the `packages` section, the Development and Transitive tables the `packages-dev` section; `src/` imports only `HopTop\Pact` and `Opis\JsonSchema`, `tests/` only `HopTop\Pact` and `PHPUnit`, `examples/` and `scripts/` only `HopTop\Pact`, besides PHP's built-in namespaces. A package change therefore updates `composer.json`, `composer.lock`, the vetted sets and this record together.
- Version review, 2026-10-20 (`composer outdated --all`, Composer 2.10.3, PHP 8.5.11), with the floor raised to 8.4: `phpunit/phpunit` 12.5.40 to 13.4.1, with its `phpunit/*` and `sebastian/*` majors; `symfony/*` 7.4 to 8.1; new `sebastian/file-filter`, `sebastian/git-state` and `symfony/polyfill-php85`. Held back for the 14-day age gate, with no security fix in their release notes: `phpunit/phpunit` `13.4.3` (2026-10-16) and `13.4.2` (2026-10-12), so the pin is `13.4.1`; `symfony/console` `v8.1.9` (2026-10-12), so the lock has `v8.1.8`; `symfony/process` `v8.1.9` (2026-10-08), so the lock has `v8.1.7`. Every other package is the latest release the floor allows. `composer audit` on the new lock: "No security vulnerability advisories found", exit 0.
