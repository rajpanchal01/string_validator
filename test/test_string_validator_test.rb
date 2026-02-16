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
end
