using JWTDotNetCore.Factory;
using JWTDotNetCore.Models;
using Newtonsoft.Json;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace JWTDotNetCore.Helpers
{
    public class Tokens
    {
        public static async Task<string> GenerateJwt(ClaimsIdentity identity, IJwtFactory jwtFactory, string userName, JwtIssuerOptions jwtOptions, Newtonsoft.Json.JsonSerializerSettings serializerSettings)
        {
            var authToken = await jwtFactory.GenerateEncodedToken(userName, identity);

            var response = new
            {
                id = identity.Claims.Single(c => c.Type == "id").Value,
                auth_token = authToken,
                expires_in = (int)jwtOptions.ValidFor.TotalSeconds
            };

            return JsonConvert.SerializeObject(response, serializerSettings);
        }
    }
}