using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;

namespace Altinn.Common.AccessToken.KeyProvider;

/// <summary>
/// A service that can provide a <see cref="SigningCredentials"/> for signing JWT tokens.
/// </summary>
public interface ISigningCredentialsProvider
{
    /// <summary>
    /// Gets the <see cref="SigningCredentials"/> to use for signing a JWT token.
    /// </summary>
    /// <param name="cancellationToken">A <see cref="CancellationToken"/>.</param>
    /// <returns>The <see cref="SigningCredentials"/>.</returns>
    Task<SigningCredentials> GetSigningCredentials(CancellationToken cancellationToken = default);
}
