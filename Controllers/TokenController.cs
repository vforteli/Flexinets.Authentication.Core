using Flexinets.Authentication;
using Flexinets.Security;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace FlexinetsAuthentication.Core.Controllers
{
    public class TokenController : Controller
    {
        private readonly RefreshTokenRepository _refreshTokenRepository;
        private readonly AdminAuthenticationProvider _adminAuthenticationProvider;
        private readonly CookieOptions _cookieOptions = new CookieOptions { HttpOnly = true, Secure = true };
        private readonly Int32 _accessTokenLifetimeSeconds;
        private readonly Int32 _refreshTokenLifetimeSeconds;
        private readonly String _jwtKey;
        private readonly String _jwtIssuer;
        private readonly String _jwtAudience;


        public TokenController(IConfiguration configuration, RefreshTokenRepository refreshTokenRepository, AdminAuthenticationProvider adminAuthenticationProvider, IHostingEnvironment hostingEnvironment)
        {
            _refreshTokenRepository = refreshTokenRepository;
            _adminAuthenticationProvider = adminAuthenticationProvider;
            _accessTokenLifetimeSeconds = Convert.ToInt32(configuration["Jwt:AccessTokenLifetimeSeconds"]);
            _refreshTokenLifetimeSeconds = Convert.ToInt32(configuration["Jwt:RefreshTokenLifetimeSeconds"]);
            _jwtKey = configuration["Jwt:Key"];
            _jwtIssuer = configuration["Jwt:Issuer"];
            _jwtAudience = configuration["Jwt:Audience"];


            if (hostingEnvironment.IsDevelopment())
            {
                _cookieOptions.Secure = false;
            }
        }


        [HttpPost("token")]
        public async Task<IActionResult> Token([FromForm]LoginModel loginModel)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(new { error = "invalid_grant" });
            }

            if (loginModel.grant_type == "password" && !String.IsNullOrEmpty(loginModel.Username) && !String.IsNullOrEmpty(loginModel.Password))
            {
                var admin = await _adminAuthenticationProvider.AuthenticateAsync(loginModel.Username, loginModel.Password);
                if (admin != null)
                {
                    var claims = new List<Claim>
                    {
                        new Claim(JwtRegisteredClaimNames.Sub, admin.AdminId.ToString()),
                        new Claim(ClaimTypes.Name, admin.AdminId.ToString())
                    };
                    claims.AddRange(admin.Roles.Select(o => new Claim(ClaimTypes.Role, ((RoleTypes)o.RoleId).ToString())));

                    var token = CreateJwtToken(claims);
                    var refreshTokenId = await CreateRefreshTokenAsync(token);

                    Response.Cookies.Append("refresh_token", refreshTokenId, _cookieOptions);
                    return Ok(new
                    {
                        access_token = new JwtSecurityTokenHandler().WriteToken(token),
                        expiration = token.ValidTo,
                        expires_in = token.ValidTo.Subtract(DateTime.UtcNow).TotalSeconds,   // todo remove, this is here to support the legacy portal during transition
                        refresh_token = refreshTokenId
                    });
                }
            }
            else if (loginModel.grant_type == "refresh_token")
            {
                var hashedTokenId = CryptoMethods.GetSHA512Hash(Request.Cookies["refresh_token"]);
                //var hashedTokenId = CryptoMethods.GetSHA512Hash(loginModel.refresh_token);    // Cookie or parameter?
                var refreshToken = await _refreshTokenRepository.GetTokenAsync(hashedTokenId);
                if (refreshToken != null)
                {
                    var oldToken = new JwtSecurityTokenHandler().ReadJwtToken(refreshToken.ProtectedTicket);
                    var newToken = CreateJwtToken(oldToken.Claims);
                    await _refreshTokenRepository.RemoveTokenAsync(hashedTokenId);
                    var newRefreshTokenId = await CreateRefreshTokenAsync(newToken);

                    Response.Cookies.Append("refresh_token", newRefreshTokenId, _cookieOptions);
                    return Ok(new
                    {
                        access_token = new JwtSecurityTokenHandler().WriteToken(newToken),
                        expiration = newToken.ValidTo,
                        expires_in = newToken.ValidTo.Subtract(DateTime.UtcNow).TotalSeconds,   // todo rmeove, this is here to support the legacy portal during transition
                        refresh_token = newRefreshTokenId
                    });
                }
            }

            return BadRequest(new { error = "invalid_grant" });
        }


        /// <summary>
        /// Create a jwt token with specified claims and default settings
        /// </summary>
        /// <param name="claims"></param>
        /// <returns></returns>
        private JwtSecurityToken CreateJwtToken(IEnumerable<Claim> claims)
        {
            return new JwtSecurityToken(
              audience: _jwtAudience,
              issuer: _jwtIssuer,
              claims: claims,
              expires: DateTime.UtcNow.AddSeconds(_accessTokenLifetimeSeconds),
              signingCredentials: new SigningCredentials(new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtKey)), SecurityAlgorithms.HmacSha256));
        }


        /// <summary>
        /// Create and new refresh token
        /// </summary>
        /// <param name="subject"></param>
        /// <returns></returns>
        private async Task<String> CreateRefreshTokenAsync(JwtSecurityToken token)
        {
            var refreshTokenId = Guid.NewGuid().ToString("n");
            var refreshToken = new RefreshTokenModel
            {
                Id = CryptoMethods.GetSHA512Hash(refreshTokenId),
                ClientId = "flexinetsportal",  // todo maybe get rid of this...
                Subject = token.Subject,
                IssuedUtc = DateTime.UtcNow,
                ExpiresUtc = DateTime.UtcNow.AddSeconds(_refreshTokenLifetimeSeconds),
                ProtectedTicket = new JwtSecurityTokenHandler().WriteToken(token)
            };

            await _refreshTokenRepository.SaveTokenAsync(refreshToken);
            return refreshTokenId;
        }
    }
}

