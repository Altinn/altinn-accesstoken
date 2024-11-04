using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace Altinn.Common.AccessTokenClient;

/// <summary>
/// Access token generator interface
/// </summary>
public interface IAccessTokenGenerator
{
    /// <summary>
    /// Generates a access token for apps needing to access platform components.
    /// </summary>
    /// <param name="issuer">Can be a app or platform component</param>
    /// <param name="app">The application creating token (app or component)</param>
    /// <param name="cancellationToken">A <see cref="CancellationToken"/>.</param>
    /// <returns>Accesstoken</returns>
    Task<string?> GenerateAccessToken(string issuer, string app, CancellationToken cancellationToken = default);

    /// <summary>
    /// Generates a access token for anyone needing to access platform components.
    /// </summary>
    /// <param name="issuer">Can be a app, function or platform component</param>
    /// <param name="app">The application creating token (app or component)</param>
    /// <param name="certificate">Certificate to generate SigningCredentials</param>
    /// <param name="cancellationToken">A <see cref="CancellationToken"/>.</param>
    /// <returns>Accesstoken</returns>
    Task<string?> GenerateAccessToken(string issuer, string app, X509Certificate2 certificate, CancellationToken cancellationToken = default);
}
