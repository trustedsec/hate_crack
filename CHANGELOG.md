# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.10.8] - 2026-07-21

### Fixed

- **Hashview `list_customers` crashed against current servers.** The `/v1/customers`
  response now returns its `users` array as native JSON (Hashview issue #229), but the
  client still ran `json.loads()` on it unconditionally, raising `TypeError` and breaking
  the entire customer → hashfile enumeration flow. Both the native-array and the legacy
  double-encoded-string shapes are now accepted.
- **Hashview hash-type parsing mis-read MD5 (mode 0).** `get_hashfile_details` selected the
  hash type with an `or` fallthrough, so the falsy `0` fell through to the response
  envelope's `type` field and returned the string `"message"`. Hash type is now read by key
  presence, and the bogus `type` fallback was removed.
- **Hashview `get_hashfile_hash_type` always returned an empty list.** It looked for
  `file_ids`/`ids`/`hashfile_ids` keys the endpoint never sends; it now reads the actual
  `hashfiles` envelope array and extracts each file id.

### Added

- **Download Hashview rule files.** New `HashviewAPI.list_rules()` and `download_rules()`
  wrap `GET /v1/rules` and `GET /v1/rules/{id}`. The server gzip-compresses plaintext rules
  on the fly, so downloads are decompressed before saving — the resulting file is usable
  directly with `hashcat -r`. Exposed via the interactive Hashview menu ("Download Rule")
  and the CLI: `hate_crack.py --hashview download-rules --rules-id <id> [--output <file>]`.
