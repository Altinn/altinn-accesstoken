using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;

using Microsoft.IdentityModel.Tokens;

namespace Altinn.AccessToken.Tests.Mock
{
    /// <summary>
    /// Represents a mechanism for creating JSON Web tokens for use in tests.
    /// </summary>
    public static class AccessTokenCreator
    {
        /// <summary>
        /// Generates a token with a self signed certificate included in the test project.
        /// </summary>
        /// <returns>A new token</returns>
        public static string GenerateToken(ClaimsPrincipal principal, TimeSpan tokenExipry, string issuer)
        {
            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
            SecurityTokenDescriptor tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(principal.Identity),
                Expires = DateTime.UtcNow.AddSeconds(tokenExipry.TotalSeconds),
                NotBefore = DateTime.UtcNow.AddSeconds(-10),
                SigningCredentials = GetSigningCredentials(issuer),
                Audience = "altinn.no",
                Issuer = issuer
            };

            SecurityToken token = tokenHandler.CreateToken(tokenDescriptor);
            string tokenstring = tokenHandler.WriteToken(token);

            return tokenstring;
        }

        private static SigningCredentials GetSigningCredentials(string issuer)
        {
            string certPath = $"{issuer}-org.pfx";

            X509Certificate2 cert = new X509Certificate2(certPath);
            return new X509SigningCredentials(cert, SecurityAlgorithms.RsaSha256);
        }
    }
}
