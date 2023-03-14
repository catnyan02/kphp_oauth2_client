<?php

namespace nyan02\kphp_oauth2_client\Token;

interface ResourceOwnerAccessTokenInterface
{
/**
* Returns the resource owner identifier, if defined.
*
* @return ?string
*/
public function getResourceOwnerId();
}