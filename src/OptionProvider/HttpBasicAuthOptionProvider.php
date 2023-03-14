<?php
namespace nyan02\kphp_oauth2_client\OptionProvider;

use nyan02\kphp_oauth2_client\Provider\AbstractProvider;
use nyan02\kphp_oauth2_client\Grant\AbstractGrant;
use nyan02\kphp_oauth2_client\Token\AccessTokenInterface;

/**
 * Add http basic auth into access token request options
 * @link https://tools.ietf.org/html/rfc6749#section-2.3.1
 */
class HttpBasicAuthOptionProvider implements OptionProviderInterface
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
    public function makeRequest($method, $accessTokenUrl, AbstractGrant $grant = null, ?AccessTokenInterface $token = null)
    {
        $encodedCredentials = base64_encode(sprintf('%s:%s', $grant->client_id, $grant->client_secret));

        $ch = curl_init($accessTokenUrl);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, ['Authorization: Basic ' . $encodedCredentials]);
        if ($token) {
            curl_setopt($ch, CURLOPT_HTTPHEADER, ['Authorization: Bearer ' . $token->getToken()]);
        }
        if ($method === AbstractProvider::METHOD_POST) {
            curl_setopt($ch, CURLOPT_POST, true);
            $post_data = http_build_query(to_array_debug($grant), '', '&', \PHP_QUERY_RFC3986);
            curl_setopt($ch, CURLOPT_POSTFIELDS, $post_data);
        }
        $response = curl_exec($ch);
        $response = !is_bool($response) ? (string) $response : '{}';
        curl_close($ch);
        return $response;
    }
}
