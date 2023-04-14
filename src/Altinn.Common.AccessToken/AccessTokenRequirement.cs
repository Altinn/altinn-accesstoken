#nullable enable

namespace Altinn.Common.AccessToken;

/// <summary>
/// The requirement used in an authorization policy to verify an access token.
/// </summary>
public class AccessTokenRequirement : IAccessTokenRequirement
{
    /// <summary>
    /// Initializes a new instance of the <see cref="AccessTokenRequirement"/> class.
    /// </summary>
    public AccessTokenRequirement()
    {
    }
}
