require 'curb'
require 'json'
require 'uri'

module Sharepoint
  OAUTH2_TENANT_ID     = ENV['OAUTH2_TENANT_ID']
  OAUTH2_CLIENT_ID     = ENV['OAUTH2_CLIENT_ID']
  OAUTH2_CLIENT_SECRET = ENV['OAUTH2_CLIENT_SECRET']
  OAUTH2_RESOURCE      = ENV['OAUTH2_RESOURCE']
  OAUTH2_TOKEN_URL     = "https://login.microsoftonline.com/#{OAUTH2_TENANT_ID}/oauth2/token"

  class Session
    class Error < Sharepoint::Error; end
    class AuthenticationFailed        < Sharepoint::Session::Error; end

    attr_accessor :site, :access_token, :expires_at

    def initialize(site)
      @site = site
      @access_token = nil
      @expires_at = nil
    end

    # Authenticate using OAuth2 client credentials grant
    def authenticate(client_id = nil, client_secret = nil, tenant_id = nil, resource = nil)
      client_id     ||= OAUTH2_CLIENT_ID
      client_secret ||= OAUTH2_CLIENT_SECRET
      tenant_id     ||= OAUTH2_TENANT_ID
      resource      ||= OAUTH2_RESOURCE

      token_url = "https://login.microsoftonline.com/#{tenant_id}/oauth2/token"
      body = {
        grant_type:    'client_credentials',
        client_id:     client_id,
        client_secret: client_secret,
        resource:      resource
      }

      http = Curl::Easy.new(token_url) do |curl|
        curl.headers['Content-Type'] = 'application/x-www-form-urlencoded'
        curl.post_body = URI.encode_www_form(body)
      end
      http.http_post

      if http.response_code != 200
        raise AuthenticationFailed.new("OAuth2 authentication failed: #{http.body_str}")
      end

      resp = JSON.parse(http.body_str)
      @access_token  = resp['access_token']
      @expires_at    = Time.now + resp['expires_in'].to_i if resp['expires_in']
      raise AuthenticationFailed.new("No access token received") unless @access_token
    end

    # Returns an empty cookie string (not used for OAuth2)
    def cookie
      ""
    end

    # Used by Sharepoint::Site to add the Authorization header
    def curl(curb)
      raise AuthenticationFailed.new("No access token, call authenticate first") unless @access_token
      curb.headers['Authorization'] = "Bearer #{@access_token}"
    end
  end
end