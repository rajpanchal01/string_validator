# StringValidator

A Ruby port of [validator.js](https://github.com/validatorjs/validator.js) — a comprehensive library of **string validators** and **sanitizers** for Ruby and Rails.

Validator.js has 23k+ GitHub stars and 18M+ weekly npm downloads. Until now, Ruby had no single gem offering the same API. Use this for API params, form input, background jobs, or any place you need to validate or sanitize strings.

## Installation

Add to your Gemfile:

```ruby
gem "string_validator"
```

Then run:

```bash
bundle install
```

Or install globally:

```bash
gem install string_validator
```

## Usage

All methods are on the `StringValidator` module. Input must be a String (validator.js is strings-only too).

### Validators

Return `true` or `false`.

```ruby
require "string_validator"

StringValidator.is_email?("foo@bar.com")        # => true
StringValidator.is_email?("invalid")            # => false

StringValidator.is_url?("https://example.com") # => true
StringValidator.is_url?("not a url")            # => false

StringValidator.is_ip?("192.168.1.1")          # => true
StringValidator.is_ip?("::1", version: 6)       # => true

StringValidator.is_empty?("  ")                 # => false
StringValidator.is_empty?("  ", ignore_whitespace: true) # => true

StringValidator.is_length?("hello", min: 1, max: 10) # => true

StringValidator.is_alpha?("abc")                # => true
StringValidator.is_alphanumeric?("user123")    # => true
StringValidator.is_numeric?("42.5")            # => true
StringValidator.is_int?("42", min: 0, max: 100) # => true
StringValidator.is_float?("3.14")              # => true

StringValidator.is_boolean?("true")            # => true
StringValidator.is_boolean?("yes", loose: true) # => true

StringValidator.is_json?('{"a":1}')             # => true
StringValidator.is_base64?("SGVsbG8=")         # => true
StringValidator.is_hex_color?("#ff0000")       # => true
StringValidator.is_uuid?("550e8400-e29b-41d4-a716-446655440000") # => true
StringValidator.is_ascii?("Hello")             # => true
StringValidator.is_slug?("my-post-title")     # => true
StringValidator.is_mac_address?("01:02:03:04:05:ab") # => true
StringValidator.is_credit_card?("4111111111111111") # => true (Luhn check)
StringValidator.is_md5?("d41d8cd98f00b204e9800998ecf8427e") # => true
StringValidator.is_hexadecimal?("0a1f")       # => true
StringValidator.is_port?("443")               # => true
StringValidator.is_iso8601?("2024-01-15")    # => true
StringValidator.is_date?("2024-01-15")        # => true
StringValidator.is_data_uri?("data:image/png;base64,...") # => true
StringValidator.is_sem_ver?("1.2.3")         # => true
StringValidator.is_mongo_id?("507f1f77bcf86cd799439011") # => true
StringValidator.is_iban?("GB82WEST12345698765432")       # => true (optional locale: "GB")
StringValidator.is_postal_code?("12345", locale: "US")   # => true (US, GB, CA, DE, IN, etc.)
StringValidator.is_jwt?("eyJhbGc...")                     # => true (structure only; no signature check)

StringValidator.contains?("hello world", "world") # => true
StringValidator.equals?("foo", "foo")          # => true
StringValidator.is_in?("red", %w[red green blue]) # => true
```

### Sanitizers

Return a transformed string (or the original if not a string).

```ruby
StringValidator.escape("<script>alert('x')</script>")
# => "&lt;script&gt;alert(&#x27;x&#x27;)&lt;&#x2F;script&gt;"

StringValidator.trim("  hello  ")              # => "hello"
StringValidator.blacklist("hello world", "ol") # => "he wrd"
StringValidator.whitelist("abc123", "0123456789") # => "123"
StringValidator.whitelist("abc123", "a-c0-9")      # => "abc123"
StringValidator.strip_low("hello\x00world")   # => "helloworld"

StringValidator.to_boolean("true")             # => true
StringValidator.to_boolean("false")           # => false
StringValidator.to_boolean("yes", strict: false) # => true
StringValidator.to_int("42")                  # => 42
StringValidator.to_float("3.14")              # => 3.14
StringValidator.normalize_email(" User@Example.COM ") # => "user@example.com"

StringValidator.unescape("&lt;tag&gt;")        # => "<tag>"
```

### Rails / ActiveModel

Use in custom validators or in models:

```ruby
# app/validators/email_validator.rb
class EmailValidator < ActiveModel::EachValidator
  def validate_each(record, attribute, value)
    return if value.blank?
    unless StringValidator.is_email?(value.to_s)
      record.errors.add(attribute, options[:message] || "is not a valid email")
    end
  end
end
```

Or inline:

```ruby
validate :email_format

def email_format
  return if email.blank?
  errors.add(:email, "invalid") unless StringValidator.is_email?(email)
end
```

### Safe validation helper

`valid?` enforces that the first argument is a String and that the validator name exists:

```ruby
StringValidator.valid?("user@example.com", :is_email?) # => true
StringValidator.valid?(nil, :is_email?)               # => raises NotStringError
StringValidator.valid?("x", :not_a_validator)          # => raises InvalidValidatorError
```

**Error classes** (all inherit from `StringValidator::Error`):

- `StringValidator::NotStringError` — input to `valid?` is not a String
- `StringValidator::InvalidValidatorError` — unknown validator name passed to `valid?`

**Robustness:** Validators return `false` (and sanitizers return the original value) when given non-strings, `nil` where it would cause errors, or when parsing/encoding fails, so you can pass user input safely without rescuing.

## Supported Ruby

Ruby 3.0+.

## License

MIT. See [LICENSE](LICENSE.txt).

## Credits

API and behavior are inspired by [validator.js](https://github.com/validatorjs/validator.js) (MIT). This gem is an independent Ruby implementation for the Ruby community.
