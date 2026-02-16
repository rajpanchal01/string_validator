# frozen_string_literal: true

require "uri"
require "json"
require "base64"
require "date"
require "time"

module StringValidator
  module Validators
    # RFC 5322 simplified email regex (validator.js compatible)
    EMAIL_REGEX = /\A[^\s@]+@[^\s@]+\.[^\s@]+\z/

    # IBAN length per ISO 3166-1 alpha-2 country code
    IBAN_LENGTHS = {
      "AD" => 24, "AE" => 23, "AL" => 28, "AT" => 20, "AZ" => 28, "BA" => 20, "BE" => 16,
      "BG" => 22, "BH" => 22, "BR" => 29, "BY" => 28, "CH" => 21, "CR" => 22, "CY" => 28,
      "CZ" => 24, "DE" => 22, "DK" => 18, "DO" => 28, "EE" => 20, "ES" => 24, "FI" => 18,
      "FO" => 18, "FR" => 27, "GB" => 22, "GE" => 22, "GI" => 23, "GL" => 18, "GR" => 27,
      "HR" => 21, "HU" => 28, "IE" => 22, "IL" => 23, "IS" => 26, "IT" => 27, "JO" => 30,
      "KW" => 30, "KZ" => 20, "LB" => 28, "LI" => 21, "LT" => 20, "LU" => 20, "LV" => 21,
      "MC" => 27, "MD" => 24, "ME" => 22, "MK" => 19, "MT" => 31, "MU" => 30, "NL" => 18,
      "NO" => 15, "PK" => 24, "PL" => 28, "PS" => 29, "PT" => 25, "QA" => 29, "RO" => 24,
      "RS" => 22, "SA" => 24, "SE" => 24, "SI" => 19, "SK" => 24, "SM" => 27, "TL" => 23,
      "TN" => 24, "TR" => 26, "UA" => 29, "VA" => 22, "VG" => 24, "XK" => 20
    }.freeze

    # Postal code regex by locale (ISO 3166-1 alpha-2). Format only, not existence check.
    POSTAL_CODE_PATTERNS = {
      "US" => /\A\d{5}(-\d{4})?\z/,
      "GB" => /\A[A-Z]{1,2}\d[A-Z\d]?\s*\d[ABD-HJLNP-UW-Z]{2}\z/i,
      "CA" => /\A[ABCEGHJKLMNPRSTVXY]\d[A-Z]\s*\d[A-Z]\d\z/i,
      "DE" => /\A\d{5}\z/,
      "FR" => /\A\d{5}\z/,
      "IN" => /\A\d{6}\z/,
      "NL" => /\A\d{4}\s*[A-Z]{2}\z/i,
      "ES" => /\A\d{5}\z/,
      "IT" => /\A\d{5}\z/,
      "AU" => /\A\d{4}\z/,
      "JP" => /\A\d{3}-?\d{4}\z/,
      "BR" => /\A\d{5}-?\d{3}\z/,
      "PL" => /\A\d{2}-?\d{3}\z/,
      "CH" => /\A\d{4}\z/,
      "AT" => /\A\d{4}\z/,
      "BE" => /\A\d{4}\z/,
      "SE" => /\A\d{3}\s*\d{2}\z/,
      "NO" => /\A\d{4}\z/,
      "DK" => /\A\d{4}\z/,
      "FI" => /\A\d{5}\z/
    }.freeze

    def is_email?(str, allow_display_name: false, require_tld: true)
      return false unless str.is_a?(String)
      s = str.strip
      s = s.gsub(/\A.*<([^>]+)>\z/, '\1') if allow_display_name
      return false if s.include?("..") || s.start_with?(".") || s.include?("@.")
      return false if require_tld && !s.include?(".")
      s.match?(EMAIL_REGEX)
    end

    def is_url?(str, protocols: %w[http https ftp], require_protocol: false, require_tld: true)
      return false unless str.is_a?(String)
      s = str.strip
      return false if s.include?(" ")
      if require_protocol
        return false unless protocols.any? { |p| s.downcase.start_with?("#{p}:") }
      end
      begin
        uri = ::URI.parse(s)
        return false if uri.host.nil? && uri.opaque.nil?
        if require_tld && uri.host && !uri.host.include?(".")
          return false
        end
        true
      rescue ::URI::InvalidURIError
        false
      end
    end

    def is_ip?(str, version: nil)
      return false unless str.is_a?(String)
      case version
      when 4, "4"
        str.match?(/\A(?:(?:25[0-5]|2[0-4]\d|1?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|1?\d\d?)\z/)
      when 6, "6"
        str.match?(/\A(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\z/) ||
          str.match?(/\A::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}\z/) ||
          str.match?(/\A(?:[0-9a-fA-F]{1,4}:){1,7}:\z/) # simplified IPv6
      else
        is_ip?(str, version: 4) || is_ip?(str, version: 6)
      end
    end

    def is_empty?(str, ignore_whitespace: false)
      return false unless str.is_a?(String)
      s = ignore_whitespace ? str.strip : str
      s.empty?
    end

    def is_length?(str, min: 0, max: nil)
      return false unless str.is_a?(String)
      len = str.length
      return false if len < min
      return false if max && len > max
      true
    end

    def is_alpha?(str, locale: "en-US")
      return false unless str.is_a?(String)
      return str.match?(/\A[a-zA-Z]+\z/) if locale.to_s.downcase.start_with?("en")
      str.match?(/\A\p{L}+\z/)
    rescue ArgumentError, Encoding::InvalidByteSequenceError
      false
    end

    def is_alphanumeric?(str, locale: "en-US")
      return false unless str.is_a?(String)
      return str.match?(/\A[a-zA-Z0-9]+\z/) if locale.to_s.downcase.start_with?("en")
      str.match?(/\A[\p{L}0-9]+\z/)
    rescue ArgumentError, Encoding::InvalidByteSequenceError
      false
    end

    def is_numeric?(str, no_symbols: false)
      return false unless str.is_a?(String)
      return str.match?(/\A\d+\z/) if no_symbols
      str.match?(/\A[-+]?\d*\.?\d+\z/)
    end

    def is_int?(str, min: nil, max: nil, allow_leading_zeroes: true)
      return false unless str.is_a?(String)
      return false if !allow_leading_zeroes && str.match?(/\A0\d+\z/)
      return false unless str.match?(/\A[-+]?\d+\z/)
      n = str.to_i
      return false if min && n < min
      return false if max && n > max
      true
    end

    def is_float?(str, min: nil, max: nil)
      return false unless str.is_a?(String)
      return false unless str.match?(/\A[-+]?\d*\.?\d+(?:[eE][-+]?\d+)?\z/)
      n = str.to_f
      return false if min && n < min
      return false if max && n > max
      true
    end

    def is_boolean?(str, loose: false)
      return false unless str.is_a?(String)
      strict = %w[true false 0 1]
      loose_list = strict + %w[yes no]
      list = loose ? loose_list : strict
      list.include?(str.downcase)
    end

    def is_json?(str, allow_primitives: false)
      return false unless str.is_a?(String)
      return true if allow_primitives && %w[true false null].include?(str.strip)
      ::JSON.parse(str)
      true
    rescue ::JSON::ParserError
      false
    end

    def is_base64?(str, url_safe: false)
      return false unless str.is_a?(String)
      regex = url_safe ? /\A[A-Za-z0-9_-]*\z/ : /\A[A-Za-z0-9+\/=]*\z/
      return false unless str.match?(regex)
      return true if str.empty?
      s = url_safe ? str.tr("-_", "+/") : str
      ::Base64.strict_decode64(s)
      true
    rescue ::ArgumentError
      false
    end

    def is_hex_color?(str, require_hashtag: false)
      return false unless str.is_a?(String)
      return false if require_hashtag && !str.start_with?("#")
      str.match?(/\A#?([0-9a-fA-F]{3}){1,2}\z/)
    end

    def is_uuid?(str, version: nil)
      return false unless str.is_a?(String)
      uuid_regex = /\A[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89ab][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\z/
      return str.match?(uuid_regex) if version.nil?
      v = version.to_s
      return false unless str.match?(uuid_regex)
      str[14] == v
    end

    def is_ascii?(str)
      return false unless str.is_a?(String)
      str.ascii_only?
    end

    def is_slug?(str)
      return false unless str.is_a?(String)
      str.match?(/\A[a-z0-9]+(?:-[a-z0-9]+)*\z/)
    end

    def is_mac_address?(str, no_separators: false)
      return false unless str.is_a?(String)
      if no_separators
        str.match?(/\A[0-9a-fA-F]{12}\z/)
      else
        str.match?(/\A[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}\z/) ||
          str.match?(/\A[0-9a-fA-F]{2}(-[0-9a-fA-F]{2}){5}\z/) ||
          str.match?(/\A[0-9a-fA-F]{2}(\.[0-9a-fA-F]{2}){5}\z/) ||
          str.match?(/\A[0-9a-fA-F]{2}( [0-9a-fA-F]{2}){5}\z/)
      end
    end

    def contains?(str, seed, ignore_case: false, min_occurrences: 1)
      return false unless str.is_a?(String)
      return false if seed.nil?
      se = seed.to_s
      s = str
      s = s.downcase if ignore_case
      se = se.downcase if ignore_case
      count = s.scan(Regexp.escape(se)).size
      count >= min_occurrences
    rescue TypeError, ArgumentError
      false
    end

    def equals?(str, comparison)
      return false unless str.is_a?(String)
      str == comparison.to_s
    rescue TypeError
      false
    end

    def is_in?(str, values)
      return false unless str.is_a?(String)
      Array(values).map(&:to_s).include?(str)
    rescue TypeError, ArgumentError
      false
    end

    def is_credit_card?(str, provider: nil)
      return false unless str.is_a?(String)
      digits = str.gsub(/\D/, "")
      return false unless digits.length >= 13 && digits.length <= 19
      return false unless luhn_valid?(digits)
      return true if provider.nil? || provider.to_s.empty?
      case provider.to_s.downcase
      when "visa" then digits.start_with?("4")
      when "mastercard", "master" then digits.match?(/\A5[1-5]\d{14}\z/) || digits.match?(/\A2(?:2[2-9]|[3-6]\d|7[01])\d{12}\z/)
      when "amex" then digits.match?(/\A3[47]\d{13}\z/)
      when "discover" then digits.start_with?("6011", "65", "644", "645", "646", "647", "648", "649") || digits.match?(/\A62\d{14}\z/)
      else true
      end
    end

    def is_md5?(str)
      return false unless str.is_a?(String)
      str.match?(/\A[0-9a-fA-F]{32}\z/)
    end

    def is_hexadecimal?(str)
      return false unless str.is_a?(String)
      str.match?(/\A[0-9a-fA-F]+\z/)
    end

    def is_port?(str)
      return false unless str.is_a?(String)
      return false unless str.match?(/\A\d+\z/)
      n = str.to_i
      n >= 0 && n <= 65_535
    end

    def is_iso8601?(str)
      return false unless str.is_a?(String)
      # Date only: validate with Date to reject e.g. 2024-13-01
      if str.match?(/\A\d{4}-\d{2}-\d{2}\z/)
        ::Date.iso8601(str)
        return true
      end
      # Allow "YYYY-MM-DD HH:MM:SS" by normalizing to use T
      s = str.sub(/\A(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2}(?:\.\d+)?)\z/, '\1T\2')
      ::Time.iso8601(s)
      true
    rescue ArgumentError, TypeError, Encoding::InvalidByteSequenceError
      false
    end

    def is_date?(str, format: nil)
      return false unless str.is_a?(String)
      if format
        ::Date.strptime(str, format.to_s)
      else
        ::Date.parse(str)
      end
      true
    rescue ArgumentError, TypeError, Encoding::InvalidByteSequenceError
      false
    end

    def is_data_uri?(str)
      return false unless str.is_a?(String)
      str.match?(/\Adata:([a-zA-Z0-9]+\/[a-zA-Z0-9+.+-]+)?;base64,[A-Za-z0-9+\/=]+\z/) ||
        str.match?(/\Adata:([a-zA-Z0-9]+\/[a-zA-Z0-9+.+-]+)?(;[a-zA-Z0-9-]+=[a-zA-Z0-9-]+)*,(%[0-9a-fA-F]{2}|[a-zA-Z0-9!\$&'*+.^_`|~-])*\z/)
    end

    def is_sem_ver?(str)
      return false unless str.is_a?(String)
      str.match?(/\A\d+\.\d+\.\d+(?:-[0-9a-zA-Z.-]+)?(?:\+[0-9a-zA-Z.-]+)?\z/)
    end

    def is_mongo_id?(str)
      return false unless str.is_a?(String)
      str.match?(/\A[0-9a-fA-F]{24}\z/)
    end

    # IBAN: ISO 13616, mod-97 check. locale = ISO 3166-1 alpha-2 to restrict to that country (optional).
    def is_iban?(str, locale: nil)
      return false unless str.is_a?(String)
      s = str.delete(" ").upcase
      return false unless s.match?(/\A[A-Z]{2}\d{2}[A-Z0-9]+\z/)
      cc = s[0, 2]
      return false unless (expected_len = IBAN_LENGTHS[cc])
      return false if locale && cc != locale.to_s.upcase[0, 2]
      return false unless s.length == expected_len
      iban_mod97_valid?(s)
    rescue ArgumentError, Encoding::InvalidByteSequenceError
      false
    end

    # Postal code format by locale (ISO 3166-1 alpha-2). Supports: US, GB, CA, DE, FR, IN, NL, etc.
    def is_postal_code?(str, locale: "US")
      return false unless str.is_a?(String)
      s = str.strip
      re = POSTAL_CODE_PATTERNS[locale.to_s.upcase]
      return false unless re
      s.match?(re)
    rescue TypeError, ArgumentError, Encoding::InvalidByteSequenceError
      false
    end

    # JWT structure: three base64url parts (header.payload.signature). Does not verify signature.
    def is_jwt?(str)
      return false unless str.is_a?(String)
      parts = str.split(".", -1)
      return false unless parts.size == 3
      parts.each do |part|
        return false unless part.match?(/\A[A-Za-z0-9_-]+\z/)
      end
      decoded = parts[0, 2].map do |p|
        pad = 4 - (p.length % 4)
        p = p.tr("-_", "+/") + ("=" * pad) if pad != 4
        ::Base64.decode64(p)
      rescue ArgumentError
        return false
      end
      ::JSON.parse(decoded[0])
      ::JSON.parse(decoded[1])
      true
    rescue ::JSON::ParserError, ArgumentError, TypeError, Encoding::InvalidByteSequenceError
      false
    end

    private

    def iban_mod97_valid?(s)
      rearranged = s[4..-1] + s[0, 4]
      num_str = rearranged.each_char.map { |c| c =~ /\A[A-Z]\z/ ? (c.ord - 55).to_s : c }.join
      remainder = 0
      num_str.scan(/.{1,7}/) do |chunk|
        remainder = (remainder.to_s + chunk).to_i % 97
      end
      remainder == 1
    rescue ArgumentError, Encoding::InvalidByteSequenceError
      false
    end

    def luhn_valid?(digits)
      sum = 0
      digits.reverse.chars.each_with_index do |c, i|
        n = c.to_i
        n *= 2 if i.odd?
        n -= 9 if n > 9
        sum += n
      end
      (sum % 10).zero?
    end
  end
end
