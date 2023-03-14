<?php
namespace nyan02\kphp_oauth2_client\Token;

use RuntimeException;

abstract class AccessTokenInterface
{
    /**
     * Returns the access token string of this instance.
     *
     * @return string
     */
    abstract public function getToken();

    /**
     * Returns the refresh token, if defined.
     *
     * @return ?string
     */
    abstract public function getRefreshToken();

    /**
     * Returns the expiration timestamp in seconds, if defined.
     *
     * @return ?int
     */
    abstract public function getExpires();

    /**
     * Checks if this token has expired.
     *
     * @return boolean true if the token has expired, false otherwise.
     * @throws RuntimeException if 'expires' is not set on the token.
     */
    abstract public function hasExpired();

    /**
     * Returns an string serialized with json_encode().
     *
     * @return string
     */
    abstract public function jsonSerialize();
}