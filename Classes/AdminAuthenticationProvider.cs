using Flexinets.Core.Database.Models;
using Flexinets.Security;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System;
using System.Threading.Tasks;

namespace FlexinetsAuthentication.Core
{
    public class AdminAuthenticationProvider
    {
        private readonly FlexinetsContext _context;


        /// <summary>
        /// Provider for authenticating admins
        /// </summary>
        /// <param name="context"></param>
        public AdminAuthenticationProvider(FlexinetsContext context)
        {
            _context = context;
        }


        /// <summary>
        /// Authenticate an admin
        /// Returns the admin with roles if successful, otherwise null
        /// </summary>
        /// <param name="username"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        public async Task<Admins> AuthenticateAsync(String username, String password)
        {
            var admin = await _context.Admins.Include(m => m.Roles).SingleOrDefaultAsync(o => (o.Username == username || o.Email == username) && o.Status == 1);

            if (admin != null && admin.Password != null)
            {
                var result = CryptoMethods.VerifyHashedPassword(admin.Password, password);
                if (result == PasswordVerificationResult.Success)
                {
                    return admin;
                }
                else if (result == PasswordVerificationResult.SuccessRehashNeeded)
                {
                    admin.Password = new PasswordHasher<Admins>().HashPassword(null, password);
                    await _context.SaveChangesAsync();
                    return admin;
                }
            }
            return null;
        }
    }
}
