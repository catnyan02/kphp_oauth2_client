<?php
namespace nyan02\kphp_oauth2_client\OptionProvider;

use nyan02\kphp_oauth2_client\Grant\AbstractGrant;
use nyan02\kphp_oauth2_client\Token\AccessTokenInterface;

/**
 * Interface for access token options provider
 */
interface OptionProviderInterface
{
    /**
     * Builds request options used for requesting an access token.
     *
     * @param string $method
     * @param string $accessTokenUrl
     * @param  AbstractGrant $grant
     * @param ?AccessTokenInterface $token
     *
     * @return string
     */
    public function makeRequest($method, $accessTokenUrl, AbstractGrant $grant=null, ?AccessTokenInterface $token=null);
}
