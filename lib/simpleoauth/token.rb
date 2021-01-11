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
                   valid_to,
                   refresh_token,
                   token_type = 'bearer')

      @access_token = access_token
      @valid_to = valid_to
      @refresh_token = refresh_token
      @token_type = token_type
    end

    # Update token with new values
    def update!(access_token, expires_in, refresh_token)
      @access_token = access_token
      @timestamp = timestamp
      @valid_to = Time.now + expires_in
      @refresh_token = refresh_token
    end

    # Check if the token has expired
    def expired?(offset)
      Time.now - offset > @valid_to
    end

    # Return a json representation of the token
    def to_json(*args)
      { access_token: @access_token,
        valid_to: @valid_to.to_i,
        refresh_token: @refresh_token,
        token_type: @token_type }.to_json(*args)
    end
  end
end
