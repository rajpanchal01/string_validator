# frozen_string_literal: true

require "test_helper"
require "string_validator"

class StringValidatorTest < Minitest::Test
  def test_is_email
    assert StringValidator.is_email?("foo@bar.com")
    assert StringValidator.is_email?("user+tag@example.co.uk")
    refute StringValidator.is_email?("invalid")
    refute StringValidator.is_email?("@nodomain.com")
    refute StringValidator.is_email?("")
  end

  def test_is_url
    assert StringValidator.is_url?("https://example.com")
    assert StringValidator.is_url?("http://foo.com/path")
    refute StringValidator.is_url?("not a url")
    refute StringValidator.is_url?("")
  end

  def test_is_ip
    assert StringValidator.is_ip?("192.168.1.1")
    assert StringValidator.is_ip?("127.0.0.1")
    assert StringValidator.is_ip?("192.168.1.1", version: 4)
    refute StringValidator.is_ip?("256.1.1.1")
    refute StringValidator.is_ip?("not an ip")
  end

  def test_is_empty
    assert StringValidator.is_empty?("")
    refute StringValidator.is_empty?("  ")
    assert StringValidator.is_empty?("  ", ignore_whitespace: true)
  end

  def test_is_length
    assert StringValidator.is_length?("hello", min: 1, max: 10)
    refute StringValidator.is_length?("", min: 1)
    refute StringValidator.is_length?("a" * 11, max: 10)
  end

  def test_is_alpha_and_alphanumeric
    assert StringValidator.is_alpha?("abc")
    refute StringValidator.is_alpha?("abc123")
    assert StringValidator.is_alphanumeric?("user123")
    refute StringValidator.is_alphanumeric?("hello world")
  end

  def test_is_int_and_float
    assert StringValidator.is_int?("42")
    assert StringValidator.is_int?("42", min: 0, max: 100)
    refute StringValidator.is_int?("3.14")
    assert StringValidator.is_float?("3.14")
    assert StringValidator.is_float?("-0.5")
  end

  def test_is_boolean
    assert StringValidator.is_boolean?("true")
    assert StringValidator.is_boolean?("false")
    assert StringValidator.is_boolean?("1")
    assert StringValidator.is_boolean?("yes", loose: true)
    refute StringValidator.is_boolean?("yes")
  end

  def test_is_json
    assert StringValidator.is_json?("{}")
    assert StringValidator.is_json?('{"a":1}')
    refute StringValidator.is_json?("not json")
  end

  def test_is_base64
    assert StringValidator.is_base64?("aGVsbG8=") # base64 of "hello"
    refute StringValidator.is_base64?("!!!")
  end

  def test_is_uuid
    assert StringValidator.is_uuid?("550e8400-e29b-41d4-a716-446655440000")
    refute StringValidator.is_uuid?("not-a-uuid")
  end

  def test_escape_and_unescape
    escaped = StringValidator.escape("<script>")
    assert_equal "&lt;script&gt;", escaped
    assert_equal "<script>", StringValidator.unescape(escaped)
  end

  def test_trim
    assert_equal "hello", StringValidator.trim("  hello  ")
  end

  def test_blacklist
    assert_equal "he wrd", StringValidator.blacklist("hello world", "ol")
  end

  def test_to_boolean
    assert_equal true, StringValidator.to_boolean("true")
    assert_equal false, StringValidator.to_boolean("false")
  end

  def test_to_int_and_to_float
    assert_equal 42, StringValidator.to_int("42")
    assert_equal 3.14, StringValidator.to_float("3.14")
  end

  def test_valid_raises_on_non_string
    assert_raises(StringValidator::NotStringError) do
      StringValidator.valid?(nil, :is_email?)
    end
    assert StringValidator.valid?("a@b.co", :is_email?)
  end

  def test_whitelist_with_ranges
    assert_equal "abc123", StringValidator.whitelist("abc123", "a-c0-9")
    assert_equal "123", StringValidator.whitelist("abc123", "0-9")
  end

  def test_is_port
    assert StringValidator.is_port?("80")
    assert StringValidator.is_port?("443")
    assert StringValidator.is_port?("65535")
    assert StringValidator.is_port?("0")
    refute StringValidator.is_port?("65536")
    refute StringValidator.is_port?("-1")
    refute StringValidator.is_port?("not a port")
  end

  def test_is_iso8601
    assert StringValidator.is_iso8601?("2024-01-15")
    assert StringValidator.is_iso8601?("2024-01-15T12:00:00Z")
    assert StringValidator.is_iso8601?("2024-01-15 12:00:00")
    refute StringValidator.is_iso8601?("not a date")
    refute StringValidator.is_iso8601?("2024-13-01")
  end

  def test_is_date
    assert StringValidator.is_date?("2024-01-15")
    assert StringValidator.is_date?("January 15, 2024")
    refute StringValidator.is_date?("not a date")
  end

  def test_is_data_uri
    assert StringValidator.is_data_uri?("data:image/png;base64,iVBORw0KGgo=")
    assert StringValidator.is_data_uri?("data:text/plain;base64,SGVsbG8=")
    refute StringValidator.is_data_uri?("http://example.com")
  end

  def test_is_sem_ver
    assert StringValidator.is_sem_ver?("1.0.0")
    assert StringValidator.is_sem_ver?("2.1.0-beta")
    refute StringValidator.is_sem_ver?("1.0")
    refute StringValidator.is_sem_ver?("v1.0.0")
  end

  def test_is_mongo_id
    assert StringValidator.is_mongo_id?("507f1f77bcf86cd799439011")
    refute StringValidator.is_mongo_id?("short")
    refute StringValidator.is_mongo_id?("507f1f77bcf86cd79943901g")
  end

  def test_normalize_email
    assert_equal "user@example.com", StringValidator.normalize_email("  User@Example.COM  ")
    assert_equal "user@example.com", StringValidator.normalize_email("user@example.com")
  end

  def test_is_iban
    # GB82 WEST 1234 5698 7654 32 is a valid test IBAN (mod 97)
    assert StringValidator.is_iban?("GB82WEST12345698765432")
    assert StringValidator.is_iban?("GB82 WEST 1234 5698 7654 32")
    assert StringValidator.is_iban?("GB82WEST12345698765432", locale: "GB")
    refute StringValidator.is_iban?("GB82WEST12345698765432", locale: "DE")
    refute StringValidator.is_iban?("invalid")
    refute StringValidator.is_iban?("GB82WEST1234569876543") # wrong length
  end

  def test_is_postal_code
    assert StringValidator.is_postal_code?("12345", locale: "US")
    assert StringValidator.is_postal_code?("12345-6789", locale: "US")
    assert StringValidator.is_postal_code?("SW1A 1AA", locale: "GB")
    assert StringValidator.is_postal_code?("K1A 0B1", locale: "CA")
    assert StringValidator.is_postal_code?("10115", locale: "DE")
    assert StringValidator.is_postal_code?("560001", locale: "IN")
    refute StringValidator.is_postal_code?("1234", locale: "US")
    refute StringValidator.is_postal_code?("invalid", locale: "US")
    refute StringValidator.is_postal_code?("12345", locale: "XX")
  end

  def test_is_jwt
    # Minimal valid JWT: header.payload.signature (each part base64url, header/payload valid JSON)
    header = Base64.strict_encode64('{"alg":"HS256","typ":"JWT"}').tr("+/", "-_").delete("=")
    payload = Base64.strict_encode64('{"sub":"123"}').tr("+/", "-_").delete("=")
    sig = Base64.strict_encode64("signature").tr("+/", "-_").delete("=")
    valid_jwt = "#{header}.#{payload}.#{sig}"
    assert StringValidator.is_jwt?(valid_jwt)
    refute StringValidator.is_jwt?("not.three.parts.here")
    refute StringValidator.is_jwt?("a.b") # only 2 parts
    refute StringValidator.is_jwt?("!!!.!!!.!!!") # invalid base64
  end

  # --- Error handling ---

  def test_valid_raises_not_string_error
    err = assert_raises(StringValidator::NotStringError) do
      StringValidator.valid?(nil, :is_email?)
    end
    assert_match(/input must be a String/i, err.message)
  end

  def test_valid_raises_invalid_validator_error
    err = assert_raises(StringValidator::InvalidValidatorError) do
      StringValidator.valid?("x", :not_a_validator)
    end
    assert_match(/unknown validator/i, err.message)
  end

  def test_valid_succeeds_with_valid_input
    assert StringValidator.valid?("a@b.co", :is_email?)
  end

  def test_contains_handles_nil_seed
    refute StringValidator.contains?("hello", nil)
  end

  def test_equals_handles_nil_comparison
    refute StringValidator.equals?("hello", nil)
    assert StringValidator.equals?("hello", "hello")
  end

  def test_blacklist_handles_nil_chars
    assert_equal "hello", StringValidator.blacklist("hello", nil)
  end

  def test_trim_handles_nil_chars
    # When chars is nil, trim defaults to stripping whitespace
    assert_equal "x", StringValidator.trim("  x  ", nil)
    assert_equal "x", StringValidator.trim("  x  ")
  end

  def test_whitelist_handles_nil_chars
    # When chars is nil, whitelist returns str unchanged (no filtering)
    assert_equal "abc", StringValidator.whitelist("abc", nil)
  end

  def test_sanitizers_return_original_on_non_string
    assert_nil StringValidator.trim(nil)
    assert_nil StringValidator.blacklist(nil, "x")
    assert_equal 42, StringValidator.to_int(42)
  end

  def test_validators_return_false_on_non_string
    refute StringValidator.is_email?(nil)
    refute StringValidator.is_email?(123)
    refute StringValidator.is_url?([])
  end
end
