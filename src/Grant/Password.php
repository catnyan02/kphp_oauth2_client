<?php

namespace nyan02\kphp_oauth2_client\Grant;

use Exception;

/**
 * Represents a resource owner password credentials grant.
 *
 * @link http://tools.ietf.org/html/rfc6749#section-1.3.3 Resource Owner Password Credentials (RFC 6749, §1.3.3)
 */
class Password extends AbstractGrant
{
    public string $grant_type = 'password';
    public ?string $username;
    public ?string $password;

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
        if (!isset($options['username'])) {
            throw new Exception('Required parameter not passed: username');
        }
        if (!isset($options['password'])) {
            throw new Exception('Required parameter not passed: username');
        }
        $this->username = (string) $options['username'];
        $this->password = (string) $options['password'];
    }
}
