# Changelog

## [0.1.0] - 2025-02-16

### Added

- Initial release
- Validators: `is_email?`, `is_url?`, `is_ip?`, `is_empty?`, `is_length?`, `is_alpha?`, `is_alphanumeric?`, `is_numeric?`, `is_int?`, `is_float?`, `is_boolean?`, `is_json?`, `is_base64?`, `is_hex_color?`, `is_uuid?`, `is_ascii?`, `is_slug?`, `is_mac_address?`, `is_credit_card?`, `is_md5?`, `is_hexadecimal?`, `contains?`, `equals?`, `is_in?`
- Sanitizers: `escape`, `unescape`, `trim`, `blacklist`, `whitelist`, `strip_low`, `to_boolean`, `to_int`, `to_float`
- `StringValidator.valid?(str, :validator_name, **options)` for safe validation with NotStringError
