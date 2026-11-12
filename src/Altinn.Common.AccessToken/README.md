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

### Running locally without Key Vault

By default `PublicSigningKeyProvider` reads the public certificate of each token issuer from the key vault in
`kvSetting:SecretUri` (secret `{issuer}-access-token-public-cert`). When `SecretUri` is empty, it reads the
certificate from the file in `AccessTokenSettings:PublicSigningCertificatePath` instead, so the app can run
locally without a key vault. When `SecretUri` is set, `PublicSigningCertificatePath` is ignored.

```cs
services.Configure<Altinn.Common.AccessToken.Configuration.AccessTokenSettings>(config.GetSection("AccessTokenSettings"));
```

```json
{
  "kvSetting": { "SecretUri": "" },
  "AccessTokenSettings": { "PublicSigningCertificatePath": "/certs/accesstoken.pfx" }
}
```

- Without `{issuer}` in the path, the same certificate is used for every issuer. This fits a local stack where all
  apps and components sign platform access tokens with one test certificate, such as localtest.
- With `{issuer}` in the path, e.g. `certs/{issuer}-org.pem`, each issuer has its own file. A token from an issuer
  without a file is rejected.
- The file can be a PEM or DER encoded certificate, or a `.pfx`/`.p12` file without a password. Only the public part
  of a `.pfx` is used.

If neither `SecretUri` nor `PublicSigningCertificatePath` is set, the app still starts, but every platform access
token is rejected. `AccessTokenHandler` logs the reason as a warning.
