# frozen_string_literal: true

require_relative "lib/string_validator/version"

Gem::Specification.new do |spec|
  spec.name          = "string_validator"
  spec.version       = StringValidator::VERSION
  spec.authors       = ["Raj Panchal"]
  spec.email         = ["rajpanchal2810@gmail.com"]

  spec.summary       = "String validators and sanitizers for Ruby - port of validator.js"
  spec.description   = "A comprehensive library of string validators (is_email?, is_url?, is_ip?, etc.) and sanitizers (escape, trim, etc.) for Ruby. Brings validator.js-style API to Ruby/Rails."
  spec.homepage      = "https://github.com/rajpanchal01/string_validator"
  spec.license       = "MIT"
  spec.required_ruby_version = ">= 3.0.0"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = spec.homepage
  spec.metadata["changelog_uri"] = "#{spec.homepage}/blob/main/CHANGELOG.md"

  spec.files = Dir.chdir(File.expand_path(__dir__)) do
    Dir["lib/**/*", "README.md", "LICENSE.txt", "CHANGELOG.md"].select { |f| File.file?(f) }
  end
  spec.require_paths = ["lib"]
end
