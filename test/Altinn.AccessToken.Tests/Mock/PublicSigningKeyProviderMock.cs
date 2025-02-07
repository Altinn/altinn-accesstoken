using System.Security.Cryptography.X509Certificates;

using Altinn.Common.AccessToken.Services;

using Microsoft.IdentityModel.Tokens;

namespace Altinn.AccessToken.Tests.Mock
{
    public class PublicSigningKeyProviderMock : IPublicSigningKeyProvider
    {
        public Task<IEnumerable<SecurityKey>> GetSigningKeys(string issuer)
        {
            List<SecurityKey> signingKeys = new List<SecurityKey>();

#if NET9_0_OR_GREATER
            X509Certificate2 cert = X509CertificateLoader.LoadCertificateFromFile($"{issuer}-org.pem");
#elif NET8_0 
            X509Certificate2 cert = new X509Certificate2($"{issuer}-org.pem");
#else 
#error This code block does not match csproj TargetFrameworks list
#endif
            SecurityKey key = new X509SecurityKey(cert);

            signingKeys.Add(key);

            return Task.FromResult(signingKeys.AsEnumerable());
        }
    }
}
