using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace Altinn.Common.AccessToken.Authentication;

/// <summary>
/// A context for <see cref="AccessTokenEvents.OnMessageReceived"/>.
/// </summary>
public class MessageReceivedContext
    : ResultContext<AccessTokenOptions>
{
    /// <summary>
    /// Initializes a new instance of <see cref="MessageReceivedContext"/>.
    /// </summary>
    public MessageReceivedContext(
        HttpContext context,
        AuthenticationScheme scheme,
        AccessTokenOptions options)
        : base(context, scheme, options)
    {
    }

    /// <summary>
    /// Platform access token. This will give the application an opportunity to retrieve a token from an alternative location.
    /// </summary>
    public string? Token { get; set; }
}
