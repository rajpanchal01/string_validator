# frozen_string_literal: true

require "uri"
require "json"
require "base64"

module StringValidator
  module Validators
    # RFC 5322 simplified email regex (validator.js compatible)
    EMAIL_REGEX = /\A[^\s@]+@[^\s@]+\.[^\s@]+\z/

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
    end

    def is_alphanumeric?(str, locale: "en-US")
      return false unless str.is_a?(String)
      return str.match?(/\A[a-zA-Z0-9]+\z/) if locale.to_s.downcase.start_with?("en")
      str.match?(/\A[\p{L}0-9]+\z/)
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
      s = str
      s = s.downcase if ignore_case
      se = ignore_case ? seed.downcase : seed
      count = s.scan(Regexp.escape(se)).size
      count >= min_occurrences
    end

    def equals?(str, comparison)
      return false unless str.is_a?(String)
      str == comparison.to_s
    end

    def is_in?(str, values)
      return false unless str.is_a?(String)
      Array(values).map(&:to_s).include?(str)
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

    private

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
