using System;

namespace Flexinets.Authentication
{
    public class RefreshTokenModel
    {
        /// <summary>
        /// Subject of refresh token
        /// </summary>
        public String Subject;

        /// <summary>
        /// Refresh token issued UTC
        /// </summary>
        public DateTime IssuedUtc;

        /// <summary>
        /// Refresh token expires UTC
        /// </summary>
        public DateTime ExpiresUtc;

        /// <summary>
        /// Serialized Jwt token
        /// </summary>
        public String AccessToken;


        public RefreshTokenModel() { }


        /// <summary>
        /// Create a refresh token model
        /// </summary>
        /// <param name="subject"></param>
        /// <param name="issuedUtc"></param>
        /// <param name="expiresIn"></param>
        /// <param name="accessToken">Serialized (jwt) access token</param>
        public RefreshTokenModel(String subject, DateTime issuedUtc, TimeSpan expiresIn, String accessToken)
        {
            Subject = subject;
            IssuedUtc = issuedUtc;
            ExpiresUtc = issuedUtc.Add(expiresIn);
            AccessToken = accessToken;
        }
    }
}