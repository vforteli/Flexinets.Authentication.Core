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
        /// Refresh token issued
        /// </summary>
        public DateTime IssuedUtc;

        /// <summary>
        /// Refresh token expires
        /// </summary>
        public DateTime ExpiresUtc;

        /// <summary>
        /// Serialized Jwt token
        /// </summary>
        public String AccessToken;


        public RefreshTokenModel() { }


        public RefreshTokenModel(String subject, DateTime issuedUtc, TimeSpan expires, String accessToken)
        {
            Subject = subject;
            IssuedUtc = issuedUtc;
            ExpiresUtc = issuedUtc.Add(expires);
            AccessToken = accessToken;
        }
    }
}