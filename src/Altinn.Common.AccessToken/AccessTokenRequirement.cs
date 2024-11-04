using System;
using System.Collections.Immutable;

namespace Altinn.Common.AccessToken;

/// <summary>
/// The requirement used in an authorization policy to verify an access token.
/// </summary>
public sealed class AccessTokenRequirement
    : IAccessTokenRequirement
{
    /// <summary>
    /// Gets the list of approved issuers to validate against.
    /// </summary>
    public ImmutableArray<string> ApprovedIssuers { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="AccessTokenRequirement"/> class with no specified issuer.
    /// </summary>
    public AccessTokenRequirement()
    {
        ApprovedIssuers = ImmutableArray<string>.Empty;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="AccessTokenRequirement"/> class with a single issuer.
    /// </summary>
    /// <param name="issuer">The issuer to validate against.</param>
    public AccessTokenRequirement(string issuer)
    {
        ApprovedIssuers = ImmutableArray.Create(issuer);
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="AccessTokenRequirement"/> class with multiple approved issuers.
    /// </summary>
    /// <param name="approvedIssuers">The list of approved issuers to validate against.</param>
    [Obsolete("Use the constructor that takes ImmutableArray<string> instead.")]
    public AccessTokenRequirement(string[] approvedIssuers)
        : this(ImmutableArray.CreateRange(approvedIssuers))
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="AccessTokenRequirement"/> class with multiple approved issuers.
    /// </summary>
    /// <param name="approvedIssuers">The list of approved issuers to validate against.</param>
    public AccessTokenRequirement(ImmutableArray<string> approvedIssuers)
    {
        ApprovedIssuers = approvedIssuers;
    }
}
