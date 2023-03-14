<?php
namespace nyan02\kphp_oauth2_client\AuthorizationParameters;

/**
 * Interface for access token options provider
 */
interface AuthorizationParametersInterface
{
    /**
     * Builds the authorization URL's query string.
     *
     * @return string Query string
     */
    public function getAuthorizationQuery();
}