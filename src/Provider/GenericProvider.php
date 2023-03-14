<?php

namespace nyan02\kphp_oauth2_client\Provider;

use Exception;
use nyan02\kphp_oauth2_client\AuthorizationParameters\GenericAuthorizationParameters;
use nyan02\kphp_oauth2_client\OptionProvider\OptionProviderInterface;
use nyan02\kphp_oauth2_client\Token\AccessTokenInterface;

/**
 * Represents a generic service provider that may be used to interact with any
 * OAuth 2.0 service provider, using Bearer token authentication.
 */
class GenericProvider extends AbstractProvider
{

    /** @var string */
    private $urlAuthorize;

    /** @var string */
    private $urlAccessToken;

    /** @var string */
    private $urlResourceOwnerDetails;

    /** @var ?string */
    private $accessTokenMethod;

    /** @var ?string */
    private $accessTokenResourceOwnerId;

    /** @var ?string */
    private $scopes = null;

    /** @var ?string */
    private $scopeSeparator;

    /** @var string */
    private $responseError = 'error';

    /** @var ?string */
    private $responseCode;

    /** @var string */
    private $responseResourceOwnerId = 'id';

    /** @var ?string */
    private $pkceMethod = null;

    /**
     * Constructs an OAuth 2.0 service provider.
     *
     * @param string $clientId
     * @param string $clientSecret
     * @param string $redirectUri
     * @param string $state
     *
     * @param string $urlAuthorize
     * @param string $urlAccessToken
     * @param string $urlResourceOwnerDetails
     *
     * @param ?string $accessTokenMethod
     * @param ?string $accessTokenResourceOwnerId
     * @param ?string $scopeSeparator
     * @param ?string $responseError
     * @param ?string $responseCode
     * @param ?string $responseResourceOwnerId
     * @param ?string $scopes
     * @param ?string $pkceMethod
     *
     * @param ?OptionProviderInterface $optionProvider
     */
    public function __construct($clientId, $clientSecret, $redirectUri, $state, $urlAuthorize, $urlAccessToken,
                                $urlResourceOwnerDetails, $accessTokenMethod=null, $accessTokenResourceOwnerId=null,
                                $scopeSeparator=null, $responseError=null, $responseCode=null,
                                $responseResourceOwnerId=null, $scopes=null, $pkceMethod=null, $optionProvider=null)
    {
        $this->urlAuthorize = $urlAuthorize;
        $this->urlAccessToken = $urlAccessToken;
        $this->urlResourceOwnerDetails = $urlResourceOwnerDetails;

        $this->accessTokenMethod = $accessTokenMethod;
        $this->accessTokenResourceOwnerId = $accessTokenResourceOwnerId;
        $this->scopeSeparator = $scopeSeparator;
        if ($responseError) $this->responseError = $responseError;
        $this->responseCode = $responseCode;
        if ($responseResourceOwnerId) $this->responseResourceOwnerId = $responseResourceOwnerId;
        $this->scopes = $scopes;
        $this->pkceMethod = $pkceMethod;

        parent::__construct($clientId, $clientSecret, $redirectUri, $state, $optionProvider);
    }

    /**
     * Returns the base URL for authorizing a client.
     *
     * Eg. https://oauth.service.com/authorize
     *
     */
    public function getBaseAuthorizationUrl() : string
    {
        return $this->urlAuthorize;
    }

    /**
     * Returns the base URL for requesting an access token.
     *
     * Eg. https://oauth.service.com/token
     *
     */
    public function getBaseAccessTokenUrl(): string
    {
        return $this->urlAccessToken;
    }

    /**
     * Returns the URL for requesting the resource owner's details.
     *
     */
    public function getResourceOwnerDetailsUrl(AccessToken $token):string
    {
        return $this->urlResourceOwnerDetails;
    }

    /**
     * Returns the default scopes used by this provider.
     *
     * This should only be the scopes that are required to request the details
     * of the resource owner, rather than all the available scopes.
     *
     */
    public function getDefaultScopes() : ?string
    {
        return $this->scopes;
    }

    public function getAuthorizationParameters(?string $state = null, ?string $scope = null,
                                               ?string $redirectUri = null) : GenericAuthorizationParameters
    {
        $state = $state ?: $this->getRandomState();
        $scope = $scope ?: $this->getDefaultScopes();
        $redirectUri = $redirectUri ?: $this->redirectUri;

        $parameters = new GenericAuthorizationParameters('code', 'auto', $this->clientId, $redirectUri, $state, $scope);

        // Store the state as it may need to be accessed later on.
        $this->state = $parameters->state;

        $pkceMethod = $this->getPkceMethod();
        if (!empty($pkceMethod)) {
            $this->pkceCode = $this->getRandomPkceCode();
            if ($pkceMethod === self::PKCE_METHOD_S256) {
                $parameters->code_challenge = trim(
                    strtr(base64_encode(hash('sha256', $this->pkceCode, true)), '+/', '-_'), '=');
            } elseif ($pkceMethod === self::PKCE_METHOD_PLAIN) {
                $parameters->code_challenge = $this->pkceCode;
            } else {
                throw new \Exception('Unknown PKCE method "' . $pkceMethod . '".');
            }
            $parameters->code_challenge_method = $pkceMethod;
        }
        return $parameters;
    }


    /**
     * @inheritdoc
     */
    protected function getAccessTokenMethod()
    {
        return $this->accessTokenMethod ?: parent::getAccessTokenMethod();
    }

    /**
     * @inheritdoc
     */
    protected function getAccessTokenResourceOwnerId()
    {
        return $this->accessTokenResourceOwnerId ?: parent::getAccessTokenResourceOwnerId();
    }

    /**
     * Returns the string that should be used to separate scopes when building
     * the URL for requesting an access token.
     *
     * @return string Scope separator, defaults to ','
     */
    protected function getScopeSeparator()
    {
        return $this->scopeSeparator ?: parent::getScopeSeparator();
    }

    /**
     * Returns the PkceMethod used by this provider.
     *
     */
    protected function getPkceMethod() : ?string
    {
        return $this->pkceMethod ?: parent::getPkceMethod();
    }

    /**
     * Checks a provider response for errors.
     *
     * @param  string $data Parsed response data
     * @throws Exception
     */
    protected function checkResponse($data)
    {
        $data = json_decode($data);
        if (!empty($data[$this->responseError])) {
            $error = $data[$this->responseError];
            if (!is_string($error)) {
                $error = var_export($error, true);
            }
            $code  = $this->responseCode;
            $code = $code && !empty($data[$code])? $data[$code] : 0;
            if (!is_int($code)) {
                $code = intval($code);
            }
            throw new Exception($error, $code);
        }
    }

    /**
     * Generates a resource owner object from a successful resource owner
     * details request.
     *
     * @param  string $response
     * @param  AccessTokenInterface $token
     * @return GenericResourceOwner
     */
    protected function createResourceOwner(string $response, AccessTokenInterface $token)
    {
        return new GenericResourceOwner($response, $this->responseResourceOwnerId);
    }

    public function getResourceOwner(AccessTokenInterface $token): GenericResourceOwner
    {
        $response = $this->fetchResourceOwnerDetails($token);

        return $this->createResourceOwner($response, $token);
    }
}