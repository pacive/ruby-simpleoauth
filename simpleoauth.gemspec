# simpleoauth.gemspec
# frozen_string_literal: true

require_relative 'lib/simpleoauth'

Gem::Specification.new do |s|
  s.name      = 'simpleoauth'
  s.version   = SimpleOAuth::VERSION
  s.date      = Time.now.strftime('%F')
  s.summary   = 'A gem for handling simple http(s) requests using OAuth2 authentication'
  s.author    = 'Anders Alfredsson'
  s.email     = 'andersb86@gmail.com'
  s.files     = ['lib/simpleoauth.rb', 'lib/simpleoauth/client.rb', 'lib/simpleoauth/token.rb']
  s.homepage  = 'https://github.com/pacive/simpleoauth'
  s.license   = 'GPL-3.0'
end
