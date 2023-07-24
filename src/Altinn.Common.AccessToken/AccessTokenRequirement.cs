#nullable enable

namespace Altinn.Common.AccessToken;

/// <summary>
/// The requirement used in an authorization policy to verify an access token.
/// </summary>
public class AccessTokenRequirement : IAccessTokenRequirement
{
    /// <summary>
    /// Gets the list of approved issuers to validate against.
    /// </summary>
    public string[] ApprovedIssuers { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="AccessTokenRequirement"/> class with no specified issuer.
    /// </summary>
    public AccessTokenRequirement()
    {
        ApprovedIssuers = new string[] { };
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="AccessTokenRequirement"/> class with a single issuer.
    /// </summary>
    /// <param name="issuer">The issuer to validate against.</param>
    public AccessTokenRequirement(string issuer)
    {
        ApprovedIssuers = new string[] { issuer };
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="AccessTokenRequirement"/> class with multiple approved issuers.
    /// </summary>
    /// <param name="approvedIssuers">The list of approved issuers to validate against.</param>
    public AccessTokenRequirement(string[] approvedIssuers)
    {
        ApprovedIssuers = approvedIssuers;
    }
}
