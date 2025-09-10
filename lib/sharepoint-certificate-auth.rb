require 'curb'
require 'json'
require 'uri'
require 'jwt'
require 'openssl'
require 'base64'

module Sharepoint
    module CertificateAuth
        class Session
            class Error < Sharepoint::Error; end
            class AuthenticationFailed < Sharepoint::Session::Error; end

            attr_accessor :site, :access_token, :expires_at

            def initialize(site)
                @site = site
                @access_token = nil
                @expires_at = nil
            end

            # Authenticate using OAuth2 client certificate
            # Pass client_id, tenant_id, resource, certificate_path, and certificate_thumbprint
            def authenticate(client_id:, tenant_id:, resource:, certificate_path:, certificate_thumbprint:)
                token_url = "https://login.microsoftonline.com/#{tenant_id}/oauth2/v2.0/token"
                now = Time.now.to_i
                payload = {
                    aud: token_url,
                    iss: client_id,
                    sub: client_id,
                    jti: SecureRandom.uuid,
                    nbf: now,
                    exp: now + 600
                }

                private_key = OpenSSL::PKey::RSA.new(::File.read(certificate_path))
                cert = OpenSSL::X509::Certificate.new(::File.read(certificate_path))
                sha1 = OpenSSL::Digest::SHA1.new(cert.to_der).digest
                x5t = Base64.urlsafe_encode64(sha1).delete('=')
                
                headers = {
                    alg: 'RS256',
                    typ: 'JWT',
                    x5t: x5t
                }

                client_assertion = JWT.encode(payload, private_key, 'RS256', headers)

                body = {
                    grant_type: 'client_credentials',
                    client_id: client_id,
                    scope: "#{resource}/.default",
                    client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                    client_assertion: client_assertion
                }

                http = Curl::Easy.new(token_url) do |curl|
                    curl.headers['Content-Type'] = 'application/x-www-form-urlencoded'
                    curl.post_body = URI.encode_www_form(body)
                end
                http.http_post

                if http.response_code != 200
                    raise AuthenticationFailed.new("OAuth2 certificate authentication failed: #{http.body_str}")
                end

                resp = JSON.parse(http.body_str)
                @access_token  = resp['access_token']
                @expires_at    = Time.now + resp['expires_in'].to_i if resp['expires_in']
                raise AuthenticationFailed.new("No access token received") unless @access_token
            end

            def cookie
                ""
            end

            def curl(curb)
                raise AuthenticationFailed.new("No access token, call authenticate first") unless @access_token
                curb.headers['Authorization'] = "Bearer #{@access_token}"
            end
        end
    end
end