# frozen_string_literal: true

module SimpleOauth
  # Handles the OAuth token used by the Client instance.
  class TokenHandler
    attr_reader :dir
    attr_accessor :file, :endpoint_auth, :encrypt, :expires_in_buffer

    def initialize(token_endpoint, client_id, client_secret)
      @token_endpoint = URI(token_endpoint)
      @client_id = client_id
      @client_secret = client_secret
      @endpoint_auth = :basic
      @encrypt = true
      @file = ".oauth_token_#{Digest::MD5.hexdigest(@token_endpoint.host + @client_id)}"
      @dir = Pathname(Dir.getwd)
      @expires_in_buffer = 10
      load_token if file.exist?(@dir + @file)
    end

    def dir=(path)
      @dir = Pathname.new(path)
    end

    # Check if the token has expired
    def expired?
      @token.expired?(@expires_in_buffer)
    end

    def access_token
      @token.access_token
    end

    def load
      data = File.read(@dir + @file)
      token = @encrypt ? decrypt_token(data) : JSON.parse(data)
      @token = Token.new(token['access_token'],
                         token['valid_to'],
                         token['refresh_token'],
                         token['token_type'])
    rescue StandardError => e
      puts "Error loading token\n#{e.message}"
    end

    def save
      data = @encrypt ? encrypt_token : @token.to_json
      File.write(@dir + @file, data)
    end

    def new_token(authorization_code, callback_url, scope)
      req_body = { grant_type: 'authorization_code',
                   code: authorization_code,
                   redirect_uri: callback_url,
                   scope: scope }

      response = JSON.parse(request_token(req_body).body)

      @token = Token.new(response['access_token'], Time.now + response['expires_in'], response['refresh_token'])

      save
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
    def renew
      req_body = { grant_type: 'refresh_token', refresh_token: @token.refresh_token }

      response = JSON.parse(request_token(req_body).body)

      @token.update!(response['access_token'], response['expires_in'], response['refresh_token'])

      save
    rescue StandardError => e
      puts "Unable to refresh token\n#{e.message}"
    end

    # Request a new token
    def request_token(params)
      header = {}

      if @endpoint_auth == :basic
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
