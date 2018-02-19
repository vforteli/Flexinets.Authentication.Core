using Flexinets.Authentication;
using Flexinets.Security;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
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
        private readonly String _jwtIssuer;
        private readonly String _jwtAudience;
        private readonly String _refreshTokenCookieName = "refresh_token";
        private readonly SigningCredentialsProvider _signingCredentialsProvider;


        public TokenController(IConfiguration configuration, RefreshTokenRepository refreshTokenRepository, AdminAuthenticationProvider adminAuthenticationProvider, IHostingEnvironment hostingEnvironment, SigningCredentialsProvider signingCredentialsProvider)
        {
            _refreshTokenRepository = refreshTokenRepository;
            _adminAuthenticationProvider = adminAuthenticationProvider;
            _accessTokenLifetimeSeconds = Convert.ToInt32(configuration["Jwt:AccessTokenLifetimeSeconds"]);
            _refreshTokenLifetimeSeconds = Convert.ToInt32(configuration["Jwt:RefreshTokenLifetimeSeconds"]);
            _jwtIssuer = configuration["Jwt:Issuer"];
            _jwtAudience = configuration["Jwt:Audience"];
            _signingCredentialsProvider = signingCredentialsProvider;


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
                        new Claim(ClaimTypes.Name, admin.AdminId.ToString()),
                        new Claim(ClaimTypes.Email, admin.Email),
                        new Claim(ClaimTypes.GivenName, admin.Firstname),
                        new Claim(ClaimTypes.Surname, admin.Lastname)
                    };
                    claims.AddRange(admin.Roles.Select(o => new Claim(ClaimTypes.Role, ((RoleTypes)o.RoleId).ToString())));

                    var jwtToken = CreateJwtToken(claims);
                    var (refreshTokenId, expiresUtc) = await CreateRefreshTokenAsync(jwtToken);

                    return GetResponse(refreshTokenId, jwtToken, expiresUtc);
                }
            }
            else if (loginModel.grant_type == "refresh_token")
            {
                if (Request.Cookies.TryGetValue(_refreshTokenCookieName, out var refreshTokenId))
                {
                    var refreshToken = await _refreshTokenRepository.GetRefreshTokenAsync(refreshTokenId);
                    if (refreshToken != null)
                    {
                        var newJwtToken = CreateJwtToken(new JwtSecurityTokenHandler().ReadJwtToken(refreshToken.AccessToken).Claims);
                        await _refreshTokenRepository.RemoveTokenAsync(refreshTokenId);
                        var (newRefreshTokenId, expiresUtc) = await CreateRefreshTokenAsync(newJwtToken);
                        return GetResponse(newRefreshTokenId, newJwtToken, expiresUtc);
                    }
                }
            }

            return BadRequest(new { error = "invalid_grant" });
        }


        [HttpPost("logout")]
        public async Task<IActionResult> Logout()
        {
            if (Request.Cookies.TryGetValue(_refreshTokenCookieName, out var refreshTokenId))
            {
                await _refreshTokenRepository.RemoveTokenAsync(refreshTokenId);
                Response.Cookies.Append(_refreshTokenCookieName, "", new CookieOptions { Expires = DateTime.UtcNow.AddYears(-1) });
            }
            return Ok();
        }




        /// <summary>
        /// Get the token response and set refresh token cookie
        /// </summary>
        /// <param name="refreshTokenId"></param>
        /// <param name="jwtToken"></param>
        /// <param name="refreshTokenExpiresUtc"></param>
        /// <returns></returns>
        private OkObjectResult GetResponse(String refreshTokenId, JwtSecurityToken jwtToken, DateTime refreshTokenExpiresUtc)
        {
            Response.Cookies.Append("refresh_token", refreshTokenId, _cookieOptions);   // much side effects such cookie
            return Ok(new
            {
                access_token = new JwtSecurityTokenHandler().WriteToken(jwtToken),
                refresh_token_expires = new DateTimeOffset(refreshTokenExpiresUtc).ToUnixTimeSeconds()
            });
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
              signingCredentials: _signingCredentialsProvider.Credentials);
        }


        /// <summary>
        /// Create and new refresh token
        /// </summary>
        /// <param name="subject"></param>
        /// <returns></returns>
        private async Task<(String refreshTokenId, DateTime refreshTokenExpiresUtc)> CreateRefreshTokenAsync(JwtSecurityToken token)
        {
            var refreshToken = new RefreshTokenModel(
                token.Subject,
                DateTime.UtcNow,
                TimeSpan.FromSeconds(_refreshTokenLifetimeSeconds),
                new JwtSecurityTokenHandler().WriteToken(token));


            var refreshTokenId = await _refreshTokenRepository.SaveRefreshTokenAsync(refreshToken);
            return (refreshTokenId, refreshToken.ExpiresUtc);
        }
    }
}

