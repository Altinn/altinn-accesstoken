## .NET Library for Access token authorization policy enforcement

This .NET library is used for setting up Access token requirements for API endpoints and enforcing the policy.

### Installation
Install the nuget with `dotnet add package Altinn.Common.AccessToken` or similar.


### Usage

This library provides classes for registering a policy for
requiring access token.

1. Add a new policy to your _AddAuthorization_ method in your Program.cs file.

    ```cs
    using Altinn.Common.AccessToken;
    (...)
    services.AddAuthorization(options =>
    {
      options.AddPolicy(
            "POLICY_PLATFORM_ACCESS",
            policy => policy.Requirements.Add(new AccessTokenRequirement()));
    });
    ```

2. Add required services for AccessTokenHandler in Program.cs

    ```cs
    using Altinn.Common.AccessToken;
    using Altinn.Common.AccessToken.Services;
    (...)

    // required service dependencies
    services.AddMemoryCache();
    services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();
    services.AddSingleton<IPublicSigningKeyProvider, PublicSigningKeyProvider>();

    // configuration
    services.Configure<Altinn.Common.AccessToken.Configuration.KeyVaultSettings>(config.GetSection("kvSetting"));

    // authorization handler
    services.AddSingleton<IAuthorizationHandler, AccessTokenHandler>();
    ```

3. To invoke the requirement on a controller endpoint decorate the endpoint with the authorize attribute

    ```cs
      [Authorize(Policy = "POLICY_PLATFORM_ACCESS")]
    ```
