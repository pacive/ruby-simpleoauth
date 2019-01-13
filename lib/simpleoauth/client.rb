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
      @token_endpoint_auth = token_endpoint_auth
      @token_file = ".oauth_token_#{Digest::MD5.hexdigest(@host.host)}"
      @token_dir = './'
      @encrypt = true
    end

    ##
    # Send authorization code to get a token for the first time
    #
    # NOTE: This gem cannot retrieve an authorization code, since this require
    # manual interaction. This has to be done by other means.
    def authorize(authorization_code, callback_url, scope)
      req_body = { grant_type: 'authorization_code',
                   code: authorization_code,
                   redirect_uri: callback_url,
                   scope: scope }

      response = JSON.parse(request_token(req_body).body)

      @token = Token.new(response['access_token'], response['expires_in'], response['refresh_token'])

      save_token
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

    # Send a Http DELETE request to path, using token as authorization
    def delete(path, headers = {})
      request(Net::HTTP::Delete.new(path, headers))
    end

    # Load token from file. If no argument is given, use +@token_dir+ instead.
    # Also sets +@token_dir+ to the provided argument.
    def load_token(dir = nil)
      @token_dir = dir if dir
      data = File.read(@token_dir + @token_file)
      token = @encrypt ? decrypt_token(data) : JSON.parse(data)
      @token = Token.new(token['access_token'],
                         token['expires_in'],
                         token['refresh_token'],
                         Time.at(token['timestamp']),
                         token['token_type'])
    rescue StandardError => e
      puts "Error loading token\n#{e.message}"
    end

    # Save Token to file. If no argument is given, use +@token_dir+ instead.
    # Also sets +@token_dir+ to the provided argument.
    def save_token(dir = nil)
      @token_dir = dir unless dir.nil?
      data = @encrypt ? encrypt_token : @token.to_json
      File.write(@token_dir + @token_file, data)
    end

    private

    # Decrypt an encrypted token
    def decrypt_token(data)
      cipher = OpenSSL::Cipher::AES.new(128, :CBC)
      cipher.decrypt
      cipher.key = @client_secret.byteslice(0..15)
      cipher.iv = @client_id.byteslice(0..15)
      json = cipher.update(data) + cipher.final
      JSON.parse(json)
    end

    # Encrypt token
    def encrypt_token
      cipher = OpenSSL::Cipher::AES.new(128, :CBC)
      cipher.encrypt
      cipher.key = @client_secret.byteslice(0..15)
      cipher.iv = @client_id.byteslice(0..15)
      cipher.update(@token.to_json) + cipher.final
    end

    # Request a new token using the refresh token
    def refresh_token
      req_body = { grant_type: 'refresh_token', refresh_token: @token.refresh_token }

      response = JSON.parse(request_token(req_body).body)

      @token.refresh!(response['access_token'], response['expires_in'], response['refresh_token'])

      save_token
    rescue StandardError => e
      puts "Unable to refresh token\n#{e.message}\n#{e.backtrace}"
      puts 'Reloading saved token'
      load_token
    end

    # Process request
    def request(req, query = nil, body = nil)
      refresh_token if @token.expired?
      make_request(req, query, body)
    rescue UnauthorizedError
      refresh_token
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

    # Request a new token
    def request_token(params)
      header = {}

      if @token_endpoint_auth == :basic
        header = { authorization: 'Basic ' + Base64.encode64("#{@client_id}:#{@client_secret}") }
      else
        params[:client_id] = @client_id
        params[:client_secret] = @client_secret
      end

      request = Net::HTTP::Post.new(@token_endpoint, header)
      request.form_data = params
      Net::HTTP.start(@host.hostname, @host.port, use_ssl: true) { |http| http.request(request) }
    end
  end
end
