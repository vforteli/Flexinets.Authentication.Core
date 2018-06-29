using System;

namespace FlexinetsAuthentication.Core
{
    public class JwtOptions
    {
        public Int32 AccessTokenLifetimeSeconds { get; set; }
        public Int32 RefreshTokenLifetimeSeconds { get; set; }
        public String Issuer { get; set; }
        public String Audience { get; set; }
    }
}
