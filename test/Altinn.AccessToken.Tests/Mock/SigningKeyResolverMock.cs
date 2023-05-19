using System.Security.Cryptography.X509Certificates;

using Altinn.Common.AccessToken.Services;

using Microsoft.IdentityModel.Tokens;

namespace Altinn.AccessToken.Tests.Mock
{
    public class SigningKeyResolverMock : IPublicSigningKeyProvider
    {
        public SigningCredentials GetSigningCredentials()
        {
            throw new NotImplementedException();
        }

        public Task<IEnumerable<SecurityKey>> GetSigningKeys(string issuer)
        {
            List<SecurityKey> signingKeys = new List<SecurityKey>();

            X509Certificate2 cert = new X509Certificate2($"{issuer}-org.pem");
            SecurityKey key = new X509SecurityKey(cert);

            signingKeys.Add(key);

            return Task.FromResult(signingKeys.AsEnumerable());
        }
    }
}
