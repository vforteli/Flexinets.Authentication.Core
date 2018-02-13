using System;

namespace Flexinets.Authentication
{
    public class RefreshTokenModel
    {
        public String Id;
        public String ClientId;
        public String Subject;
        public DateTime IssuedUtc;
        public DateTime ExpiresUtc;
        public String ProtectedTicket;
    }
}