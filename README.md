This package provides OAuth 2.0 client support for the KPHP

###Installation
To install, use composer:

```composer require nyan02/kphp_oauth2_client```

###Usage
This package implements Generic Provider. However, it is better to use
specific providers. There are currently 2 supported providers:
- google (nyan02/kphp_oauth2_google)
- keycloak (nyan02/kphp_oauth2_keycloak)

This package implements Abstract Provider, that can be used to
create new packages for other providers. Generally, to write
a new provider you need to implement a new Provider/YourProvider.php
by inheriting from Abstract provider, a Provider/YourResourceOwner.php
by implementing ResourceOwnerInterface and 
a new AuthorizationParameters/YourAuthorizationParameters by
implementing AuthorizationParametersInterface

You can find simple example on how to implement a new provider 
in source code for nyan02/kphp_oauth2_google. Usually you won't
need to change much, just to account for specifics of a certain
provider.

This framework allows to use the same flow for all the providers
that inherit from this package. The only step that differs between
providers is configuring a provider.

###Authorization Code Flow
After configuring provider we want to get Authorization Code. We use
method getAuthorizationParameters() to get parameters from the provider
including permission scopes and other info needed for generating
AuthorizationUrl.

Next we generate AuthorizationUrl using method getAuthorizationUrl($params)
and passing parameters we've got before. Now that we have the Url we can
redirect the user to Authorization page of provider.

Once we've got Authorization Code we create a placeholder class for it

```new AuthorizationCode($provider->getClientId(), $provider->getClientSecret(), $provider->getRedirectUri())```

And pass it to getAccessToken method together with the code we've got.

```$token = $provider->getAccessToken($grant, ['code' => $_GET['code']]);```

Now we have the Access Token to Resource.
