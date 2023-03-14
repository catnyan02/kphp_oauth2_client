<?php

namespace nyan02\kphp_oauth2_client\Provider;

/**
 * Represents a generic resource owner for use with the GenericProvider.
 */
class GenericResourceOwner implements ResourceOwnerInterface
{
    /**
     * @var string
     */
    protected $response;

    /**
     * @var string
     */
    protected $resourceOwnerId;

    /**
     * @param string $response
     * @param string $resourceOwnerId
     */
    public function __construct(string $response, $resourceOwnerId)
    {
        $this->response = $response;
        $this->resourceOwnerId = $resourceOwnerId;
    }

    /**
     * Returns the identifier of the authorized resource owner.
     *
     * @return string
     */
    public function getId()
    {
        return json_decode($this->response)[$this->resourceOwnerId];
    }

    public function toJSON(): string
    {
        return JsonEncoder::encode($this);
    }
}