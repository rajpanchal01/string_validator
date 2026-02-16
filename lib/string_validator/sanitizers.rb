# frozen_string_literal: true

module StringValidator
  module Sanitizers
    HTML_ESCAPE = {
      "&" => "&amp;",
      "<" => "&lt;",
      ">" => "&gt;",
      '"' => "&quot;",
      "'" => "&#x27;",
      "/" => "&#x2F;"
    }.freeze

    def escape(str)
      return str unless str.is_a?(String)
      str.gsub(/[&<>"'\/]/, HTML_ESCAPE)
    rescue ArgumentError, Encoding::InvalidByteSequenceError
      str
    end

    def trim(str, chars = nil)
      return str unless str.is_a?(String)
      if chars.nil? || chars == ""
        return str.strip
      end
      chars_str = chars.to_s
      str.gsub(/\A[#{Regexp.escape(chars_str)}]+|[#{Regexp.escape(chars_str)}]+\z/, "")
    rescue TypeError, ArgumentError, Encoding::InvalidByteSequenceError
      str
    end

    def blacklist(str, chars)
      return str unless str.is_a?(String)
      return str if chars.nil?
      return str unless chars.is_a?(String)
      str.delete(chars)
    rescue ArgumentError, Encoding::InvalidByteSequenceError
      str
    end

    def whitelist(str, chars)
      return str unless str.is_a?(String)
      return str if chars.nil?
      allowed = expand_whitelist_chars(chars)
      str.each_char.select { |c| allowed.include?(c) }.join
    rescue TypeError, ArgumentError, Encoding::InvalidByteSequenceError
      str
    end

    def strip_low(str, keep_new_lines: false)
      return str unless str.is_a?(String)
      if keep_new_lines
        str.each_char.select { |c| c.ord >= 32 || c == "\n" }.join
      else
        str.each_char.select { |c| c.ord >= 32 }.join
      end
    rescue ArgumentError, Encoding::InvalidByteSequenceError
      str
    end

    def to_boolean(str, strict: true)
      return str unless str.is_a?(String)
      s = str.downcase.strip
      return true if s == "true" || s == "1"
      return false if s == "false" || s == "0"
      return true if !strict && %w[yes y].include?(s)
      return false if !strict && %w[no n].include?(s)
      str
    rescue ArgumentError, Encoding::InvalidByteSequenceError
      str
    end

    def to_int(str, radix: 10)
      return str unless str.is_a?(String)
      Integer(str, radix.to_i)
    rescue ArgumentError, TypeError
      str
    end

    def to_float(str)
      return str unless str.is_a?(String)
      Float(str)
    rescue ArgumentError, TypeError
      str
    end

    def unescape(str)
      return str unless str.is_a?(String)
      str
        .gsub("&amp;", "&")
        .gsub("&lt;", "<")
        .gsub("&gt;", ">")
        .gsub("&quot;", '"')
        .gsub("&#x27;", "'")
        .gsub("&#x2F;", "/")
    rescue ArgumentError, Encoding::InvalidByteSequenceError
      str
    end

    def normalize_email(str, lowercase_domain: true)
      return str unless str.is_a?(String)
      s = str.strip
      return s if s.empty?
      local, at, domain = s.rpartition("@")
      return s if at != "@" || local.empty? || domain.empty?
      local = local.downcase
      domain = domain.downcase if lowercase_domain
      "#{local}@#{domain}"
    rescue ArgumentError, Encoding::InvalidByteSequenceError
      str
    end

    private

    def expand_whitelist_chars(chars)
      return "" unless chars.is_a?(String)
      set = +""
      i = 0
      while i < chars.length
        if i + 2 < chars.length && chars[i + 1] == "-"
          from = chars[i].ord
          to = chars[i + 2].ord
          from, to = to, from if from > to
          set << (from..to).map(&:chr).join
          i += 3
        else
          set << chars[i]
          i += 1
        end
      end
      set
    rescue RangeError, ArgumentError, Encoding::InvalidByteSequenceError
      ""
    end
  end
end
