using JWTDotNetCore.Factory;
using JWTDotNetCore.Helpers;
using JWTDotNetCore.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Newtonsoft.Json;
using System.Security.Claims;
using System.Threading.Tasks;

namespace JWTDotNetCore.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {

        private readonly JwtIssuerOptions jwtOptions;
        private readonly JsonSerializerSettings _serializerSettings;
        private readonly IJwtFactory jwtFactory;
        public UserController(IOptions<JwtIssuerOptions> _jwtOptions, IJwtFactory _jwtFactory)
        {
            jwtOptions = _jwtOptions.Value;
            
            jwtFactory = _jwtFactory;

            _serializerSettings = new JsonSerializerSettings
            {
                Formatting = Formatting.Indented
            };

        }
        

        // GET: api/User/20190423
        [HttpPost]
        public async Task<ActionResult> Validate([FromBody]string userName, string password)
        {
            var identity = await GetClaimsIdentity(userName, password);
            if (identity == null)
            {
                return BadRequest(Errors.AddErrorToModelState("login_failure", "Invalid token.", ModelState));
            }

            var jwt = await Tokens.GenerateJwt(identity, jwtFactory,userName, jwtOptions, new JsonSerializerSettings { Formatting = Formatting.Indented });
            return new OkObjectResult(jwt);

        }

        private async Task<ClaimsIdentity> GetClaimsIdentity(string userName, string password)
        {
            if (string.IsNullOrEmpty(userName) || string.IsNullOrEmpty(password))
                return await Task.FromResult<ClaimsIdentity>(null);


            // get the user to verifty
            //var userToVerify = await _userManager.FindByNameAsync(userName);
            int userId = 1;

            //here, user/pwd already verified , so need to create claims identity
            return await Task.FromResult(jwtFactory.GenerateClaimsIdentity(userName, userId.ToString()));

            //// get the user to verifty
/*
            var userToVerify = await _userManager.FindByNameAsync(userName);

            if (userToVerify == null) return await Task.FromResult<ClaimsIdentity>(null);

            // check the credentials
            if (await _userManager.CheckPasswordAsync(userToVerify, password))
            {
                return await Task.FromResult(_jwtFactory.GenerateClaimsIdentity(userName, userToVerify.Id));
            }

            // Credentials are invalid, or account doesn't exist
            return await Task.FromResult<ClaimsIdentity>(null);*/

        }


    }
}