# Changelog

## [Unreleased]

### Added

- Validators: `is_port?`, `is_iso8601?`, `is_date?`, `is_data_uri?`, `is_sem_ver?`, `is_mongo_id?`, `is_iban?`, `is_postal_code?`, `is_jwt?`
- `is_iban?`: ISO 13616 IBAN with mod-97 check; optional `locale:` (ISO 3166-1 alpha-2) to restrict country
- `is_postal_code?`: format check by `locale:` (US, GB, CA, DE, FR, IN, NL, ES, IT, AU, JP, BR, PL, CH, AT, BE, SE, NO, DK, FI)
- `is_jwt?`: three-part base64url structure and valid JSON in header/payload (no signature verification)
- Sanitizer: `normalize_email` (strip + lowercase, with optional `lowercase_domain: true`)

### Changed

- `whitelist` now supports character ranges (e.g. `"a-c0-9"` for letters a–c and digits 0–9)
- Fixed indentation in `is_url?` for clarity

### Error handling

- **`StringValidator::InvalidValidatorError`** — raised by `valid?` when the validator name is unknown
- **`valid?`** — checks that the validator exists before calling (no more `NoMethodError` on typos)
- **Validators** — return `false` on bad input: non-String, `nil` seed/comparison/values, and rescue `ArgumentError`, `TypeError`, `Encoding::InvalidByteSequenceError` where parsing or encoding can fail (`is_alpha?`, `is_alphanumeric?`, `contains?`, `equals?`, `is_in?`, `is_iso8601?`, `is_date?`, `is_iban?`, `is_postal_code?`, `is_jwt?`)
- **Sanitizers** — return the original value on non-String or on error; `trim`, `blacklist`, `whitelist` handle `nil` chars; `to_int`/`to_float` rescue `TypeError`; all sanitizers rescue encoding/argument errors where applicable

## [0.1.0] - 2025-02-16

### Added

- Initial release
- Validators: `is_email?`, `is_url?`, `is_ip?`, `is_empty?`, `is_length?`, `is_alpha?`, `is_alphanumeric?`, `is_numeric?`, `is_int?`, `is_float?`, `is_boolean?`, `is_json?`, `is_base64?`, `is_hex_color?`, `is_uuid?`, `is_ascii?`, `is_slug?`, `is_mac_address?`, `is_credit_card?`, `is_md5?`, `is_hexadecimal?`, `contains?`, `equals?`, `is_in?`
- Sanitizers: `escape`, `unescape`, `trim`, `blacklist`, `whitelist`, `strip_low`, `to_boolean`, `to_int`, `to_float`
- `StringValidator.valid?(str, :validator_name, **options)` for safe validation with NotStringError
