<?php
namespace nyan02\kphp_oauth2_client\AuthorizationParameters;

/**
 * Represents a schema for authorization request.
 *
 * An authorization grant is a credential representing the resource
 * owner's authorization (to access its protected resources) used by the
 * client to obtain an access token.  OAuth 2.0 defines four
 * grant types -- authorization code, implicit, resource owner password
 * credentials, and client credentials -- as well as an extensibility
 * mechanism for defining additional types.
 *
 * @link http://tools.ietf.org/html/rfc6749#section-1.3 Authorization Grant (RFC 6749, §1.3)
 */
class GenericAuthorizationParameters implements AuthorizationParametersInterface
{
    public string $response_type;
    public string $client_id;
    public string $approval_prompt;
    public string $redirect_uri;
    public string $state;
    public ?string $scope;
    public ?string $code_challenge_method;
    public ?string $code_challenge;

    /**
     * Needed in order to use KPHP JsonEncoder.
     *
     */
    public function __construct(string $response_type, string $approval_prompt, string $client_id, string $redirect_uri,
                                   string $state, ?string $scope){

        $this->response_type = $response_type;
        $this->approval_prompt = $approval_prompt;
        $this->client_id = $client_id;
        $this->redirect_uri = $redirect_uri;
        $this->scope = $scope;
        $this->state = $state;

    }

    /**
     * Builds the authorization URL's query string.
     *
     * @return string Query string
     */
    public function getAuthorizationQuery()
    {
        return http_build_query($this, '', '&', \PHP_QUERY_RFC3986);
    }
}