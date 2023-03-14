<?php

namespace nyan02\kphp_oauth2_client\Provider;

/**
 * Classes implementing `ResourceOwnerInterface` may be used to represent
 * the resource owner authenticated with a service provider.
 */
interface ResourceOwnerInterface
{
    /**
     * Returns the identifier of the authorized resource owner.
     *
     * @return string
     */
    public function getId();


    public function toJSON(): string;
}