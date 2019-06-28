using JWTDotNetCore.Models;
using Microsoft.Extensions.Options;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Threading.Tasks;

namespace JWTDotNetCore.Factory
{

    public interface IJwtFactory
    {
        Task<string> GenerateEncodedToken(string userName, ClaimsIdentity identity);
        ClaimsIdentity GenerateClaimsIdentity(string userName, string id);
    }

    public class JwtFactory : IJwtFactory
    {
        private readonly Models.JwtIssuerOptions jwtOptions;

        public JwtFactory(IOptions<JwtIssuerOptions> _jwtOptions)
        {
            jwtOptions = _jwtOptions.Value;
            ThrowIfInvalidOptions(jwtOptions);
        }

        public async Task<string> GenerateEncodedToken(string userName, ClaimsIdentity identity)
        {
            try
            {
                var claims = new[]
             {
                 new Claim(Microsoft.IdentityModel.JsonWebTokens.JwtRegisteredClaimNames.Sub, userName),
                 new Claim(Microsoft.IdentityModel.JsonWebTokens.JwtRegisteredClaimNames.Jti, await jwtOptions.JtiGenerator()),
                 new Claim(Microsoft.IdentityModel.JsonWebTokens.JwtRegisteredClaimNames.Iat, ToUnixEpochDate(jwtOptions.IssuedAt).ToString(), ClaimValueTypes.Integer64),
                 identity.FindFirst(Helpers.Constants.Strings.JwtClaimIdentifiers.Rol),
                 identity.FindFirst(Helpers.Constants.Strings.JwtClaimIdentifiers.Id)
             };

                // Create the JWT security token and encode it.
                var jwt = new System.IdentityModel.Tokens.Jwt.JwtSecurityToken(
                    issuer: jwtOptions.Issuer,
                    audience: jwtOptions.Audience,
                    claims: claims,
                    notBefore: jwtOptions.NotBefore,
                    expires: jwtOptions.Expiration,
                    signingCredentials: jwtOptions.SigningCredentials);

                var encodedJwt = new JwtSecurityTokenHandler().WriteToken(jwt);

                return encodedJwt;
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }

        public ClaimsIdentity GenerateClaimsIdentity(string userName, string id)
        {
            return new ClaimsIdentity(new System.Security.Principal.GenericIdentity(userName, "Token"), new[]
            {
                new Claim(Helpers.Constants.Strings.JwtClaimIdentifiers.Id, id),
                new Claim(Helpers.Constants.Strings.JwtClaimIdentifiers.Rol, Helpers.Constants.Strings.JwtClaims.ApiAccess)
            });
        }

        /// <returns>Date converted to seconds since Unix epoch (Jan 1, 1970, midnight UTC).</returns>
        private static long ToUnixEpochDate(DateTime date)
          => (long)Math.Round((date.ToUniversalTime() -
                               new DateTimeOffset(1970, 1, 1, 0, 0, 0, TimeSpan.Zero))
                              .TotalSeconds);

        private static void ThrowIfInvalidOptions(JwtIssuerOptions options)
        {
            if (options == null) throw new ArgumentNullException(nameof(options));

            if (options.ValidFor <= TimeSpan.Zero)
            {
                throw new ArgumentException("Must be a non-zero TimeSpan.", nameof(JwtIssuerOptions.ValidFor));
            }

            if (options.SigningCredentials == null)
            {
                throw new ArgumentNullException(nameof(JwtIssuerOptions.SigningCredentials));
            }

            if (options.JtiGenerator == null)
            {
                throw new ArgumentNullException(nameof(JwtIssuerOptions.JtiGenerator));
            }
        }
    }
}