using System;

namespace Flexinets.Authentication
{
    public class RefreshTokenModel
    {
        public String Subject;
        public DateTime IssuedUtc;
        public DateTime ExpiresUtc;
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