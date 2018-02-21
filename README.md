# ruby-simpleoauth
A simple ruby gem for handling OAuth 2 authentication

SimpleOAuth is a gem that handles OAuth2 authentication that is used by many
web APIs to provide access to resources and/or interact with remote services.

### Example:
```ruby
require 'simpleoauth'

oauth = SimpleOAuth::Client.new('api.example.com', '/oauth/token', 'oauth_client_id', 'oauth_client_secret')
oauth.load_token('/path/to/file/')
puts oauth.get('/resource').body
puts oauth.post('/resource', { data: 'some_data' }.to_json, 'content-type' => 'application/json')
```
