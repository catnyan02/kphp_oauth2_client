<?php
namespace nyan02\kphp_oauth2_client\Grant;

/**
 * Represents a type of authorization grant.
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
abstract class AbstractGrant
{
    public string $client_id;
    public string $client_secret;
    public string $redirect_uri;
    public ?string $code_verifier = null;

    public function __construct(string $client_id, string $client_secret, string $redirect_uri,
                                string $code_verifier=null){

        $this->client_id = $client_id;
        $this->client_secret = $client_secret;
        $this->redirect_uri = $redirect_uri;
        $this->code_verifier = $code_verifier;

    }

    /**
     * Returns the name of this grant, eg. 'grant_name', which is used as the
     * grant type when encoding URL query parameters.
     *
     * @return string
     */
    abstract function getName():string;

    /**
     * Prepares an access token request's parameters by checking that all
     * required parameters are set, then merging with any given defaults.
     *
     * @param  array $options
     */
    abstract public function prepareRequestParameters(array $options);

    /**
     * Returns this grant's name as its string representation. This allows for
     * string interpolation when building URL query parameters.
     *
     * @return string
     */

    public function __toString()
    {
        return $this->getName();
    }
}
