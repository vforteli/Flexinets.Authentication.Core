using Microsoft.IdentityModel.Tokens;

namespace FlexinetsAuthentication.Core
{
    /// <summary>
    /// SigningCredentialsProvider for injecting credentials into controller
    /// </summary>
    public class SigningCredentialsProvider
    {
        public SigningCredentials Credentials { get; }

        public SigningCredentialsProvider(SigningCredentials credentials) => Credentials = credentials;
    }
}
