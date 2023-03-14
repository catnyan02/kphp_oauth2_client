<?php
namespace nyan02\kphp_oauth2_client\Token;

use JsonEncoder;
use RuntimeException;

/**
 * Represents an access token.
 *
 * @link http://tools.ietf.org/html/rfc6749#section-1.4 Access Token (RFC 6749, §1.4)
 */
class AccessToken extends AccessTokenInterface implements ResourceOwnerAccessTokenInterface
{
    /** @var string */
    protected $accessToken;

    /** @var ?int */
    protected $expires;

    /** @var ?string */
    protected $refreshToken;

    /** @var ?string */
    protected $resourceOwnerId;

    private static ?int $timeNow = 0;

    /**
     * Set the time now. This should only be used for testing purposes.
     *
     * @param int $timeNow the time in seconds since epoch
     * @return void
     */
    public static function setTimeNow($timeNow)
    {
        self::$timeNow = $timeNow;
    }

    /**
     * Reset the time now if it was set for test purposes.
     *
     * @return void
     */
    public static function resetTimeNow()
    {
        self::$timeNow = null;
    }

    /**
     * @return ?int
     */
    public function getTimeNow()
    {
        return self::$timeNow ? self::$timeNow : time();
    }

    /**
     * Constructs an access token.
     *
     * @param string $access_token
     * @param ?string $refresh_token
     * @param ?int $expires
     * @param ?string $resource_owner_id
     */
    public function __construct($access_token, $refresh_token=null, $expires=null, $resource_owner_id=null)
    {
        $this->accessToken = $access_token;
        $this->resourceOwnerId = $resource_owner_id;
        $this->refreshToken = $refresh_token;
        $this->expires = $expires;
    }

    /**
     * Returns the access token string of this instance.
     *
     * @return string
     */
    public function getToken()
    {
        return $this->accessToken;
    }

    /**
     * Returns the refresh token, if defined.
     *
     * @return ?string
     */
    public function getRefreshToken()
    {
        return $this->refreshToken;
    }

    /**
     * Returns the expiration timestamp in seconds, if defined.
     *
     * @return ?int
     */
    public function getExpires()
    {
        return $this->expires;
    }

    /**
     * Returns the resource owner identifier, if defined.
     *
     * @return ?string
     */
    public function getResourceOwnerId()
    {
        return $this->resourceOwnerId;
    }

    /**
     * Checks if this token has expired.
     *
     * @return boolean true if the token has expired, false otherwise.
     * @throws RuntimeException if 'expires' is not set on the token.
     */
    public function hasExpired()
    {
        $expires = $this->getExpires();

        if (empty($expires)) {
            throw new RuntimeException('"expires" is not set on the token');
        }

        return $expires < time();
    }

    /**
     * Returns an string serialized with json_encode().
     *
     * @return string
     */
    public function jsonSerialize()
    {
        $parameters = JsonEncoder::encode($this);
        return $parameters;
    }
}