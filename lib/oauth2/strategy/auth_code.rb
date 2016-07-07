module OAuth2
  module Strategy
    # The Authorization Code Strategy
    #
    # @see http://tools.ietf.org/html/draft-ietf-oauth-v2-15#section-4.1
    class AuthCode < Base
      # The required query parameters for the authorize URL
      #
      # @param [Hash] params additional query parameters
      def authorize_params(params = {})
        params.merge('response_type' => 'code', 'client_id' => @client.id)
      end

      # The authorization URL endpoint of the provider
      #
      # @param [Hash] params additional query parameters for the URL
      def authorize_url(params = {})
        @client.authorize_url(authorize_params.merge(params))
      end

      # Retrieve an access token given the specified validation code.
      #
      # @param [String] code The Authorization Code value
      # @param [Hash] params additional params
      # @param [Hash] opts options
      # @note that you must also provide a :redirect_uri with most OAuth 2.0 providers
      def get_token(code, params = {}, opts = {})
        #logger = ::Logger.new($stdout)
        #logger.info "Params before #{params.to_s}"
        params[:redirect_uri] = params[:redirect_uri].split('?').first if params.has_key? :redirect_uri
        params = {'grant_type' => 'authorization_code', 'code' => code}.merge(client_params).merge(params)
        #logger.info "Params after #{params.to_s}"
        @client.get_token(params, opts)
      end

      def progname=
        "OAuth2::Strategy::AuthCode"
      end
    end
  end
end
