<?php

namespace nyan02\kphp_oauth2_client\Grant;

/**
 * Represents a client credentials grant.
 *
 * @link http://tools.ietf.org/html/rfc6749#section-1.3.4 Client Credentials (RFC 6749, §1.3.4)
 */
class ClientCredentials extends AbstractGrant
{
    /**
     * Returns the name of this grant, eg. 'grant_name', which is used as the
     * grant type when encoding URL query parameters.
     *
     * @return string
     */
    function getName():string
    {
        return $this->grant_type;
    }

    public string $grant_type = 'client_credentials';

    /**
     * Prepares an access token request's parameters by checking that all
     * required parameters are set, then merging with any given defaults.
     *
     * @param  array $options
     */
    public function prepareRequestParameters(array $options)
    {}
}
