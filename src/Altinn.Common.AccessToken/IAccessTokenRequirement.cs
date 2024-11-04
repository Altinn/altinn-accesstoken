using System.Collections.Immutable;
using Microsoft.AspNetCore.Authorization;

namespace Altinn.Common.AccessToken;

/// <summary>
/// This interface describes the implementation of an access token requirement in policy based authorization.
/// </summary>
public interface IAccessTokenRequirement
    : IAuthorizationRequirement
{
    /// <summary>
    /// Gets the list of approved issuers to validate against.
    /// </summary>
    public ImmutableArray<string> ApprovedIssuers { get; }
}
