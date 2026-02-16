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
    end

    def trim(str, chars = nil)
      return str unless str.is_a?(String)
      if chars
        str.gsub(/\A[#{Regexp.escape(chars)}]+|[#{Regexp.escape(chars)}]+\z/, "")
      else
        str.strip
      end
    end

    def blacklist(str, chars)
      return str unless str.is_a?(String)
      str.delete(chars)
    end

    def whitelist(str, chars)
      return str unless str.is_a?(String)
      str.each_char.select { |c| chars.include?(c) }.join
    end

    def strip_low(str, keep_new_lines: false)
      return str unless str.is_a?(String)
      if keep_new_lines
        str.each_char.select { |c| c.ord >= 32 || c == "\n" }.join
      else
        str.each_char.select { |c| c.ord >= 32 }.join
      end
    end

    def to_boolean(str, strict: true)
      return str unless str.is_a?(String)
      s = str.downcase.strip
      return true if s == "true" || s == "1"
      return false if s == "false" || s == "0"
      return true if !strict && %w[yes y].include?(s)
      return false if !strict && %w[no n].include?(s)
      str
    end

    def to_int(str, radix: 10)
      return str unless str.is_a?(String)
      Integer(str, radix)
    rescue ArgumentError
      str
    end

    def to_float(str)
      return str unless str.is_a?(String)
      Float(str)
    rescue ArgumentError
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
    end
  end
end
