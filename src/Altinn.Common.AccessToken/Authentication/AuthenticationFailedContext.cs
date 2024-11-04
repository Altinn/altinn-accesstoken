using System;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace Altinn.Common.AccessToken.Authentication;

/// <summary>
/// A context for <see cref="AccessTokenEvents.OnAuthenticationFailed"/>.
/// </summary>
public class AuthenticationFailedContext 
    : ResultContext<AccessTokenOptions>
{
    /// <summary>
    /// Initializes a new instance of <see cref="AuthenticationFailedContext"/>.
    /// </summary>
    public AuthenticationFailedContext(
        HttpContext context,
        AuthenticationScheme scheme,
        AccessTokenOptions options,
        Exception exception)
        : base(context, scheme, options) 
    {
        Exception = exception;
    }

    /// <summary>
    /// Gets or sets the exception associated with the authentication failure.
    /// </summary>
    public Exception Exception { get; }
}
