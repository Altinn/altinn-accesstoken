using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Tokens;

namespace Altinn.Common.AccessToken.Authentication;

/// <summary>
/// A context for <see cref="AccessTokenEvents.OnTokenValidated"/>.
/// </summary>
public class TokenValidatedContext 
    : ResultContext<AccessTokenOptions>
{
    /// <summary>
    /// Initializes a new instance of <see cref="TokenValidatedContext"/>.
    /// </summary>
    public TokenValidatedContext(
        HttpContext context,
        AuthenticationScheme scheme,
        AccessTokenOptions options,
        SecurityToken securityToken)
        : base(context, scheme, options) 
    {
        SecurityToken = securityToken;
    }

    /// <summary>
    /// Gets or sets the validated security token.
    /// </summary>
    public SecurityToken SecurityToken { get; }
}
