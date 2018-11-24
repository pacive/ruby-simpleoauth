# token.rb
# frozen_string_literal: true

module SimpleOAuth
  # A class for storing and accessing instances of OAuth tokens
  class Token
    # The access token used for authenticating with the resource provider
    attr_reader :access_token

    # The refresh token used to get a new token if the token has expired
    attr_reader :refresh_token

    # The type of token. Currently only supports Bearer-type tokens
    attr_reader :token_type

    # Create a new token object
    def initialize(access_token,
                   expires_in,
                   refresh_token,
                   timestamp = Time.now,
                   token_type = 'bearer')

      @access_token = access_token
      @expires_in = expires_in - 5
      @refresh_token = refresh_token
      @token_type = token_type
      @timestamp = timestamp
    end

    # Update token with new values
    def refresh!(access_token, expires_in, refresh_token, timestamp = Time.now)
      @access_token = access_token
      @timestamp = timestamp
      @expires_in = expires_in - 5
      @refresh_token = refresh_token
    end

    # Check if the token has expired
    def expired?
      Time.now > @timestamp + @expires_in
    end

    # Return a json representation of the token
    def to_json
      { access_token: @access_token,
        timestamp: @timestamp.to_i,
        expires_in: @expires_in,
        refresh_token: @refresh_token,
        token_type: @token_type }.to_json
    end
  end
end
