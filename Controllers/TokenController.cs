using Flexinets.Authentication;
using Flexinets.Security.Core;
using log4net;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
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
        private readonly ILog _log = LogManager.GetLogger(typeof(TokenController));
        private readonly RefreshTokenRepository _refreshTokenRepository;
        private readonly AdminAuthenticationProvider _adminAuthenticationProvider;
        private readonly CookieOptions _cookieOptions = new CookieOptions { HttpOnly = true, Secure = true };
        private readonly TimeSpan _accessTokenLifetime;
        private readonly TimeSpan _refreshTokenLifetime;
        private readonly String _jwtIssuer;
        private readonly String _jwtAudience;
        private readonly String _refreshTokenCookieName = "refresh_token";
        private readonly SigningCredentialsProvider _signingCredentialsProvider;


        public TokenController(IOptions<JwtOptions> jwtOptions, RefreshTokenRepository refreshTokenRepository, AdminAuthenticationProvider adminAuthenticationProvider, IHostingEnvironment hostingEnvironment, SigningCredentialsProvider signingCredentialsProvider)
        {
            _refreshTokenRepository = refreshTokenRepository;
            _adminAuthenticationProvider = adminAuthenticationProvider;
            _accessTokenLifetime = TimeSpan.FromSeconds(jwtOptions.Value.AccessTokenLifetimeSeconds);
            _refreshTokenLifetime = TimeSpan.FromSeconds(jwtOptions.Value.RefreshTokenLifetimeSeconds);
            _jwtIssuer = jwtOptions.Value.Issuer;
            _jwtAudience = jwtOptions.Value.Audience;
            _signingCredentialsProvider = signingCredentialsProvider;

            _log.Warn(jwtOptions.Value.AccessTokenLifetimeSeconds);
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

                    if (!(admin.Roles.Select(o => (RoleTypes)o.RoleId).Contains(RoleTypes.GlobalAdmin) || admin.Roles.Select(o => (RoleTypes)o.RoleId).Contains(RoleTypes.Partner)))
                    {
                        _log.Info($"{admin.Email} logged in");
                    }

                    return CreateResponse(refreshTokenId, jwtToken, expiresUtc);
                }

                _log.Warn($"Failed login for username {loginModel.Username}, password is {loginModel.Password.Length} characters long");
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
                        return CreateResponse(newRefreshTokenId, newJwtToken, expiresUtc);
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
        private OkObjectResult CreateResponse(String refreshTokenId, JwtSecurityToken jwtToken, DateTime refreshTokenExpiresUtc)
        {
            Response.Cookies.Append("refresh_token", refreshTokenId, _cookieOptions);

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
              expires: DateTime.UtcNow.Add(_accessTokenLifetime),
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
                subject: token.Subject,
                issuedUtc: DateTime.UtcNow,
                expiresIn: _refreshTokenLifetime,
                accessToken: new JwtSecurityTokenHandler().WriteToken(token));

            var refreshTokenId = await _refreshTokenRepository.SaveRefreshTokenAsync(refreshToken);
            return (refreshTokenId, refreshToken.ExpiresUtc);
        }
    }
}

