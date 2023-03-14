<?php
namespace nyan02\kphp_oauth2_client\Grant;

use Exception;

/**
 * Represents a refresh token grant.
 *
 * @link http://tools.ietf.org/html/rfc6749#section-6 Refreshing an Access Token (RFC 6749, §6)
 */
class RefreshToken extends AbstractGrant
{
    public string $grant_type = 'refresh_token';
    public ?string $refresh_token;

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

    public function prepareRequestParameters(array $options)
    {
        if (!isset($options['refresh_token'])) {
            throw new Exception('Required parameter not passed: refresh_token');
        }
        $this->refresh_token = (string) $options['refresh_token'];
    }
}
