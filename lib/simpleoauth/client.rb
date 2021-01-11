# simpleoauth.rb
# frozen_string_literal: true

module SimpleOAuth
  # A class for handling the OAuth protocol
  class Client
    # Directory to save the OAuth token to. Defaults to the current directory
    attr_accessor :token_dir

    # Filename to save the OAuth token to. Defaults to +.oauth_token_+ \+ a Hex MD5 hash of the resource provider hostname
    attr_accessor :token_file

    # The method of authentication that is used when requesting a token
    attr_accessor :token_endpoint_auth

    # Time buffer to expire the token early (in seconds)
    attr_accessor :token_expires_in_buffer

    # Whether to encrypt the token information before saving it to a file. Defaults to +true+
    #
    # NOTE: The data is encrypted with 128-bit AES encryption using the +client_secret+ and +client_id+
    # as key and iv. An attacker that gets hold of these can easily decrypt the token. It's
    # therefore recommended to keep your credentials in a secure place.
    attr_accessor :encrypt

    # URI object containing the hostname of the resource provider
    attr_reader :host

    # The path to the resource provider's token endpoint
    attr_reader :token_endpoint

    ##
    # Create a new OAuth client
    #
    # [host]  the host name of the resource provider, e.g. +api.example.com+
    # [token_endpoint]  the relative path to the token enpoint, e.g. +/oauth/token+
    # [client_id/client_secret]  the consumers client id and secret
    # [token_endpoint_auth]  \[optional\] specifies how the consumer should provide authentication
    #                        to the resource provider when requesting a token. Default is to pass the
    #                        client id and secret in the message body,
    #                        but can be set to +:basic+ to use http basic auth instead.

    def initialize(host, token_endpoint, client_id, client_secret, token_endpoint_auth = nil)
      @host = URI(host)
      @token_endpoint = token_endpoint
      @client_id = client_id
      @client_secret = client_secret
      @token = TokenHandler.new(host + token_endpoint, client_id, client_secret)
      @token.endpoint_auth = token_endpoint_auth
    end

    ##
    # Send authorization code to get a token for the first time
    #
    # NOTE: This gem cannot retrieve an authorization code, since this require
    # manual interaction. This has to be done by other means.
    def authorize(authorization_code, callback_url, scope)
      @token.new_token(authorization_code, callback_url, scope)
    rescue StandardError => e
      puts "Unable to authorize\n#{e.message}"
    end

    # Sent a Http GET request to path, using token as authorization
    def get(path, query = nil, headers = {})
      request(Net::HTTP::Get.new(path, headers), query)
    end

    # Send a Http POST request to path, using token as authorization
    def post(path, body, headers = {})
      request(Net::HTTP::Post.new(path, headers), nil, body)
    end

    # Send a Http PUT request to path, using token as authorization
    def put(path, body, headers = {})
      request(Net::HTTP::Put.new(path, headers), nil, body)
    end

    # Send a Http PATCH request to path, using token as authorization
    def patch(path, body, headers = {})
      request(Net::HTTP::Patch.new(path, headers), nil, body)
    end

    # Send a Http DELETE request to path, using token as authorization
    def delete(path, headers = {})
      request(Net::HTTP::Delete.new(path, headers))
    end

    def method_missing(method, *args, &block)
      meth = method.gsub(/\Atoken_/, '')
      @token.send(meth, *args, &block)
    end

    def respond_to_missing?(method)
      case method
      when /token_dir=?/,
           /token_file=?/,
           /token_endpoint_auth=?/,
           /token_expires_in_buffer=?/,
           /encrypt=?/
           then true
      else super
      end
    end

    private

    # Process request
    def request(req, query = nil, body = nil)
      @token.renew if @token.expired?
      make_request(req, query, body)
    rescue UnauthorizedError
      @token.renew
      make_request(req, query, body)
    end

    # Make a request and return the response
    def make_request(req, query, body)
      req.path.concat('?', URI.encode_www_form(query)) if query
      req.body = body if body

      req['Authorization'] = "Bearer #{@token.access_token}"
      res = Net::HTTP.start(@host.hostname, @host.port, use_ssl: true) { |http| http.request(req) }
      raise UnauthorizedError if res.code == 401

      res
    end
  end
end
