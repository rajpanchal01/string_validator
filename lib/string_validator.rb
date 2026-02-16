# frozen_string_literal: true

require "string_validator/version"
require "string_validator/validators"
require "string_validator/sanitizers"

module StringValidator
  extend Validators
  extend Sanitizers

  class Error < StandardError; end
  class NotStringError < Error; end

  def self.valid?(str, validator_name, **options)
    raise NotStringError, "input must be a String" unless str.is_a?(String)
    public_send(validator_name, str, **options)
  end
end
