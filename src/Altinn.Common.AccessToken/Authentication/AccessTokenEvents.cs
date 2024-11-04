using System;
using System.Threading.Tasks;

namespace Altinn.Common.AccessToken.Authentication;

/// <summary>
/// Specifies events which the bearer token handler invokes to enable developer control over the authentication process.
/// </summary>
public class AccessTokenEvents
{
    /// <summary>
    /// Invoked if authentication fails during request processing. The exceptions will be re-thrown after this event unless suppressed.
    /// </summary>
    public Func<AuthenticationFailedContext, Task> OnAuthenticationFailed { get; set; } = context => Task.CompletedTask;

    /// <summary>
    /// Invoked when a protocol message is first received.
    /// </summary>
    public Func<MessageReceivedContext, Task> OnMessageReceived { get; set; } = static context => Task.CompletedTask;

    /// <summary>
    /// Invoked after the security token has passed validation and a ClaimsIdentity has been generated.
    /// </summary>
    public Func<TokenValidatedContext, Task> OnTokenValidated { get; set; } = context => Task.CompletedTask;

    /// <summary>
    /// Invoked if exceptions are thrown during request processing. The exceptions will be re-thrown after this event unless suppressed.
    /// </summary>
    public virtual Task AuthenticationFailed(AuthenticationFailedContext context) 
        => OnAuthenticationFailed(context);

    /// <summary>
    /// Invoked when a protocol message is first received.
    /// </summary>
    /// <param name="context">The <see cref="MessageReceivedContext"/>.</param>
    public virtual Task MessageReceivedAsync(MessageReceivedContext context)
        => OnMessageReceived(context);

    /// <summary>
    /// Invoked after the security token has passed validation and a ClaimsIdentity has been generated.
    /// </summary>
    public virtual Task TokenValidated(TokenValidatedContext context) 
        => OnTokenValidated(context);
}
