using System;
using System.Collections.Generic;
using Altinn.Common.AccessToken.KeyProvider;
using Microsoft.AspNetCore.Authentication;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Altinn.Common.AccessToken.Authentication;

/// <summary>
/// Contains the options used to authenticate using altinn access tokens.
/// </summary>
public sealed class AccessTokenOptions
    : AuthenticationSchemeOptions
{
    private IPublicSigningKeyProvider? _publicSigningKeyProvider;
    private readonly JsonWebTokenHandler _defaultTokenHandler = new JsonWebTokenHandler
    {
        MapInboundClaims = true,
    };

    /// <summary>
    /// Initializes a new instance of the <see cref="AccessTokenOptions"/> class.
    /// </summary>
    public AccessTokenOptions()
    {
        Events = new();
        TokenHandlers = [_defaultTokenHandler];
    }

    /// <summary>
    /// Disable access token verification
    /// </summary>
    public bool DisableAccessTokenVerification { get; set; }

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
    /// Defines whether the bearer token should be stored in the
    /// <see cref="AuthenticationProperties"/> after a successful authorization.
    /// </summary>
    public bool SaveToken { get; set; } = true;

    /// <summary>
    /// Gets the ordered list of <see cref="TokenHandler"/> used to validate access tokens.
    /// </summary>
    public IList<TokenHandler> TokenHandlers { get; private set; }

    /// <summary>
    /// Gets or sets the <see cref="IPublicSigningKeyProvider"/> to use for validating the access tokens.
    /// </summary>
    public IPublicSigningKeyProvider PublicSigningKeyProvider
    {
        get => _publicSigningKeyProvider ?? throw new InvalidOperationException($"{nameof(PublicSigningKeyProvider)} was not set");
        set => _publicSigningKeyProvider = value;
    }

    /// <summary>
    /// The object provided by the application to process events raised by the bearer token authentication handler.
    /// The application may implement the interface fully, or it may create an instance of <see cref="AccessTokenEvents"/>
    /// and assign delegates only to the events it wants to process.
    /// </summary>
    public new AccessTokenEvents Events
    {
        get { return (AccessTokenEvents)base.Events!; }
        set { base.Events = value; }
    }
}
