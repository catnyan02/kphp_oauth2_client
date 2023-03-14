<?php
namespace nyan02\kphp_oauth2_client\Provider;

use InvalidArgumentException;
use nyan02\kphp_oauth2_client\AuthorizationParameters\AuthorizationParametersInterface;
use nyan02\kphp_oauth2_client\Grant\AbstractGrant;
use nyan02\kphp_oauth2_client\OptionProvider\OptionProviderInterface;
use nyan02\kphp_oauth2_client\OptionProvider\PostAuthOptionProvider;
use nyan02\kphp_oauth2_client\Token\AccessToken;
use nyan02\kphp_oauth2_client\Token\AccessTokenInterface;
use UnexpectedValueException;

/**
 * Represents a service provider (authorization server).
 *
 * @link http://tools.ietf.org/html/rfc6749#section-1.1 Roles (RFC 6749, §1.1)
 */
abstract class AbstractProvider
{

    /** @var ?string Key used in a token response to identify the resource owner. */
    const ACCESS_TOKEN_RESOURCE_OWNER_ID = null;

    /** @var string HTTP method used to fetch access tokens. */
    const METHOD_GET = 'GET';

    /** @var string HTTP method used to fetch access tokens. */
    const METHOD_POST = 'POST';

    /**
     * @var string PKCE method used to fetch authorization token.
     * The PKCE code challenge will be hashed with sha256 (recommended).
     */
    const PKCE_METHOD_S256 = 'S256';

    /**
     * @var string PKCE method used to fetch authorization token.
     * The PKCE code challenge will be sent as plain text, this is NOT recommended.
     * Only use `plain` if no other option is possible.
     */
    const PKCE_METHOD_PLAIN = 'plain';

    protected string $clientId;
    protected string $clientSecret;
    protected string $redirectUri;
    protected ?string $state;
    protected ?string $pkceCode = null;

    protected OptionProviderInterface $optionProvider;

    /**
     * Constructs an OAuth 2.0 service provider.
     *
     * @param string $clientId
     * @param string $clientSecret
     * @param string $redirectUri
     * @param ?string $state
     * @param ?OptionProviderInterface $optionProvider
     */
    public function __construct($clientId, $clientSecret, $redirectUri, $state, $optionProvider=null)
    {
        $this->clientId = $clientId;
        $this->clientSecret = $clientSecret;
        $this->redirectUri = $redirectUri;
        $this->state = $state;

        if (!$optionProvider) {
            $optionProvider = new PostAuthOptionProvider();
        }
        $this->setOptionProvider($optionProvider);
    }

    /**
     * Sets the option provider instance.
     *
     */
    public function setOptionProvider(OptionProviderInterface $provider): AbstractProvider
    {
        $this->optionProvider = $provider;

        return $this;
    }

    /**
     * Returns the option provider instance.
     *
     */
    public function getOptionProvider(): OptionProviderInterface
    {
        return $this->optionProvider;
    }

    /**
     * Returns the current value of the state parameter.
     *
     * This can be accessed by the redirect handler during authorization.
     *
     */
    public function getState(): ?string
    {
        return $this->state;
    }

    /**
     * Returns the client id.
     *
     */
    public function getClientId(): string
    {
        return $this->clientId;
    }

    /**
     * Returns the client secret.
     *
     */
    public function getClientSecret(): string
    {
        return $this->clientSecret;
    }

    /**
     * Returns the client secret.
     *
     */
    public function getRedirectUri(): string
    {
        return $this->redirectUri;
    }

    /**
     * Set the value of the pkceCode parameter.
     *
     * When using PKCE this should be set before requesting an access token.
     *
     */
    public function setPkceCode(string $pkceCode): AbstractProvider
    {
        $this->pkceCode = $pkceCode;
        return $this;
    }

    /**
     * Returns the current value of the pkceCode parameter.
     *
     * This can be accessed by the redirect handler during authorization.
     *
     */
    public function getPkceCode(): ?string
    {
        return $this->pkceCode;
    }

    /**
     * Returns the base URL for authorizing a client.
     *
     * Eg. https://oauth.service.com/authorize
     *
     */
    abstract public function getBaseAuthorizationUrl(): string;

    /**
     * Returns the base URL for requesting an access token.
     *
     * Eg. https://oauth.service.com/token
     *
     */
    abstract public function getBaseAccessTokenUrl(): string;

    /**
     * Returns the URL for requesting the resource owner's details.
     *
     */
    abstract public function getResourceOwnerDetailsUrl(AccessTokenInterface $token): string;

    /**
     * Returns a new random string to use as the state parameter in an
     * authorization flow.
     *
     * @param  int $length Length of the random string to be generated.
     */
    protected function getRandomState($length = 32): string
    {
        // Converting bytes to hex will always double length. Hence, we can reduce
        // the amount of bytes by half to produce the correct length.
        return bin2hex(openssl_random_pseudo_bytes($length / 2));
    }

    /**
     * Returns a new random string to use as PKCE code_verifier and
     * hashed as code_challenge parameters in an authorization flow.
     * Must be between 43 and 128 characters long.
     *
     * @param  int $length Length of the random string to be generated.
     */
    protected function getRandomPkceCode($length = 64): ?string
    {
        return (string) substr(strtr(base64_encode(openssl_random_pseudo_bytes($length)), '+/', '-_'), 0, $length) ?? null;
    }


    /**
     * Returns the default scopes used by this provider.
     *
     * This should only be the scopes that are required to request the details
     * of the resource owner, rather than all the available scopes.
     *
     */
    abstract protected function getDefaultScopes(): ?string;

    /**
     * Returns the string that should be used to separate scopes when building
     * the URL for requesting an access token.
     *
     * @return string Scope separator, defaults to ','
     */
    protected function getScopeSeparator()
    {
        return ',';
    }

    /**
     * Returns the PkceMethod used by this provider.
     *
     */
    protected function getPkceMethod(): ?string
    {
        return null;
    }


    /**
     * Builds the authorization URL.
     *
     * @param AuthorizationParametersInterface $params
     *
     * @return string Authorization URL
     */
    public function getAuthorizationUrl(AuthorizationParametersInterface $params)
    {
        $base = $this->getBaseAuthorizationUrl();
        $query = $params->getAuthorizationQuery();

        return $this->appendQuery($base, $query);
    }

    /**
     * Appends a query string to a URL.
     *
     * @param  string $url The URL to append the query to
     * @param  string $query The HTTP query string
     * @return string The resulting URL
     */
    protected function appendQuery($url, $query)
    {
        $query = trim($query, '?&');

        if ($query) {
            $glue = strstr($url, '?') === false ? '?' : '&';
            return $url . $glue . $query;
        }

        return $url;
    }

    /**
     * Returns the method to use when requesting an access token.
     *
     * @return string HTTP method
     */
    protected function getAccessTokenMethod()
    {
        return self::METHOD_POST;
    }

    /**
     * Returns the key used in the access token response to identify the resource owner.
     *
     * @return ?string Resource owner identifier key
     */
    protected function getAccessTokenResourceOwnerId()
    {
        return self::ACCESS_TOKEN_RESOURCE_OWNER_ID;
    }

    /**
     * Returns the full URL to use when requesting an access token.
     *
     * @return string
     */
    protected function getAccessTokenUrl(AbstractGrant $grant)
    {
        $url = $this->getBaseAccessTokenUrl();

        if ($this->getAccessTokenMethod() === self::METHOD_GET) {
            $query = http_build_query(to_array_debug($grant), '', '&', \PHP_QUERY_RFC3986);
            return $this->appendQuery($url, $query);
        }

        return $url;
    }

    /**
     * Returns a prepared request for requesting an access token.
     *
     * @return string
     */
    protected function makeAccessTokenRequest(AbstractGrant $grant)
    {
        $method = $this->getAccessTokenMethod();
        $url = $this->getAccessTokenUrl($grant);

        return $this->getOptionProvider()->makeRequest($method, $url, $grant);
    }

    /**
     * Check if a value is an expiration timestamp or second value.
     *
     * @param int $value
     * @return bool
     */
    protected function isExpirationTimestamp($value)
    {
        // If the given value is larger than the original OAuth 2 draft date,
        // assume that it is meant to be a (possible expired) timestamp.
        $oauth2InceptionDate = 1349067600; // 2012-10-01
        return ($value > $oauth2InceptionDate);
    }

    /**
     * Requests an access token using a specified grant and option set.
     *
     * @param  AbstractGrant $grant
     * @param  array $options
     * @return AccessTokenInterface
     * @throws IdentityProviderException
     */
    public function getAccessToken($grant, array $options = [])
    {

        $grant->prepareRequestParameters($options);
        $response = $this->makeAccessTokenRequest($grant);
        $this->checkResponse($response);
        $decoded_response = json_decode($response, true);

        if (false === is_array($decoded_response)) {
            throw new UnexpectedValueException(
                'Invalid response received from Authorization Server. Expected JSON.'
            );
        }

        if (empty($decoded_response['access_token'])) {
            throw new InvalidArgumentException('Required option not passed: "access_token"');
        }

        $access_token = (string) $decoded_response['access_token'];
        $refresh_token = null;
        $expires = null;
        $resource_owner_id = $this->getAccessTokenResourceOwnerId();

        if ($resource_owner_id !== null) {
            $resource_owner_id = array_key_exists($resource_owner_id, $decoded_response) ? $decoded_response[$resource_owner_id] : null;
        }

        if (!empty($decoded_response['refresh_token'])) {
            $refresh_token = (string) $decoded_response['refresh_token'];
        }

        // We need to know when the token expires. Show preference to
        // 'expires_in' since it is defined in RFC6749 Section 5.1.
        // Defer to 'expires' if it is provided instead.
        if (isset($decoded_response['expires_in'])) {
            if (!is_numeric($decoded_response['expires_in'])) {
                throw new \InvalidArgumentException('expires_in value must be an integer');
            }

            $expires_in = $decoded_response['expires_in'] != 0 ? time() + $decoded_response['expires_in'] : 0;
        } elseif (!empty($decoded_response['expires'])) {
            // Some providers supply the seconds until expiration rather than
            // the exact timestamp. Take a best guess at which we received.
            $expires = intval($decoded_response['expires']);
            if ($expires){
                if (!$this->isExpirationTimestamp($expires)) {
                    $expires += time();
                }
            }
        }

        return new AccessToken($access_token, $refresh_token, $expires, (string) $resource_owner_id);
    }

    /**
     * Returns an authenticated request json result.
     *
     * @param  string $method
     * @param  string $url
     * @param AccessTokenInterface $token
     *
     * @return string
     */
    public function getAuthenticatedRequest($method, $url, $token)
    {
        return $this->getOptionProvider()->makeRequest($method, $url, null, $token);
    }

    /**
     * Checks a provider response for errors.
     *
     * @param  string $data Parsed response data
     * @throws Exception
     */
    abstract protected function checkResponse($data);

    /**
     * Generates a resource owner object from a successful resource owner
     * details request.
     *
     * @param  string $response
     * @param  AccessTokenInterface $token
     * @return ResourceOwnerInterface
     */
    abstract protected function createResourceOwner(string $response, AccessTokenInterface $token);

    /**
     * Requests and returns the resource owner of given access token.
     *
     * @param  AccessTokenInterface $token
     */
    abstract public function getResourceOwner(AccessTokenInterface $token);

    /**
     * Requests resource owner details.
     *
     * @param  AccessTokenInterface $token
     * @return string
     */
    protected function fetchResourceOwnerDetails(AccessTokenInterface $token)
    {
        $url = $this->getResourceOwnerDetailsUrl($token);

        return $this->getAuthenticatedRequest(self::METHOD_GET, $url, $token);
    }
}