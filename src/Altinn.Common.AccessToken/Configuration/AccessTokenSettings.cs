#nullable enable

namespace Altinn.Common.AccessToken.Configuration;

/// <summary>
/// Settings for access token
/// </summary>
public class AccessTokenSettings
{
    /// <summary>
    /// Disable access token verification
    /// </summary>
    public bool DisableAccessTokenVerification { get; set;  }

    /// <summary>
    /// The Access token headerId
    /// </summary>
    public string AccessTokenHeaderId { get; set; } = "PlatformAccessToken";

    /// <summary>
    /// Cache lifetime for certs
    /// </summary>
    public int CacheCertLifetimeInSeconds { get; set; } = 3600;

    /// <summary>
    /// ID for cache token in 
    /// </summary>
    public string AccessTokenHttpContextId { get; set; } = "accesstokencontextid";

    /// <summary>
    /// Path to the public certificate used to validate access tokens when no key vault is configured
    /// (<see cref="KeyVaultSettings.SecretUri"/> is empty), e.g. when running locally. Ignored when a key vault is configured.
    /// </summary>
    /// <remarks>
    /// The placeholder <c>{issuer}</c> is replaced with the token issuer, so each issuer can have its own file,
    /// e.g. <c>certs/{issuer}-org.pem</c>. Without the placeholder the same certificate is used for every issuer.
    /// The file can be a PEM or DER encoded certificate, or a PKCS#12 file (<c>.pfx</c> or <c>.p12</c>) without a password,
    /// in which case only the public part is used.
    /// </remarks>
    public string? PublicSigningCertificatePath { get; set; }
}
