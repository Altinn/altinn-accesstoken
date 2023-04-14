using System.Security.Claims;

namespace Altinn.AccessToken.Tests.Mock
{
    public static class PrincipalUtil
    {
        public static ClaimsPrincipal CreateClaimsPrincipal()
        {
            ClaimsIdentity identity = new ClaimsIdentity("mock-org");
            return new ClaimsPrincipal(identity);
        }
    }
}
