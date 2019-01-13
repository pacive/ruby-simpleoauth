# simpleoauth.rb
# frozen_string_literal: true

require 'json'
require 'digest'
require 'base64'
require 'net/http'
require 'openssl'
require 'time'
require 'simpleoauth/client'
require 'simpleoauth/token'

##
# SimpleOAuth is a gem that handles OAuth2 authentication that is used by many
# web APIs to provide access to resources and/or interact with remote services.
#
# ===Example:
#
#   require 'simpleoauth'
#
#   oauth = SimpleOAuth::Client.new('api.example.com', '/oauth/token', 'oauth_client_id', 'oauth_client_secret')
#   oauth.load_token('/path/to/file/')
#   puts oauth.get('/resource').body
#   puts oauth.post('/resource', { data: 'some_data' }.to_json, 'content-type' => 'application/json')
module SimpleOAuth
  # Version of the gem
  VERSION = '0.5.1'

  class OAuthError < StandardError
  end

  class UnauthorizedError < OAuthError
  end
end
