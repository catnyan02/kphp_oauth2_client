<?php

namespace nyan02\kphp_oauth2_client\Grant;

use Exception;

/**
 * Represents an authorization code grant.
 *
 * @link http://tools.ietf.org/html/rfc6749#section-1.3.1 Authorization Code (RFC 6749, §1.3.1)
 */
class AuthorizationCode extends AbstractGrant
{
    public string $grant_type = 'authorization_code';
    public ?string $code;

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

    /**
     * Prepares an access token request's parameters by checking that all
     * required parameters are set, then merging with any given defaults.
     *
     * @param  array $options
     */
    public function prepareRequestParameters(array $options)
        {
            if (!isset($options['code'])) {
                throw new Exception('Required parameter not passed: code');
            }
            $this->code = (string) $options['code'];
        }
}

