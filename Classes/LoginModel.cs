using System.ComponentModel.DataAnnotations;

namespace FlexinetsAuthentication.Core
{
    public class LoginModel
    {
        [Required]
        public string grant_type { get; set; }


        public string refresh_token { get; set; }


        public string Username { get; set; }


        public string Password { get; set; }
    }
}
