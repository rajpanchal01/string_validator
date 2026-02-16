# frozen_string_literal: true

require "string_validator/version"
require "string_validator/validators"
require "string_validator/sanitizers"

module StringValidator
  extend Validators
  extend Sanitizers

  class Error < StandardError; end
  class NotStringError < Error; end
  class InvalidValidatorError < Error; end

  def self.valid?(str, validator_name, **options)
    raise NotStringError, "input must be a String" unless str.is_a?(String)
    name = validator_name.to_sym
    raise InvalidValidatorError, "unknown validator: #{name.inspect}" unless respond_to?(name, true)
    public_send(name, str, **options)
  rescue NoMethodError => e
    raise InvalidValidatorError, "unknown validator: #{validator_name.inspect} (#{e.message})"
  end
end
