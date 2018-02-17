﻿using Flexinets.Core.Database.Models;
using Flexinets.Security;
using log4net;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace FlexinetsAuthentication.Core
{
    public class AdminAuthenticationProvider
    {
        private readonly FlexinetsContext _context;
        private readonly IEnumerable<String> _resetReturnDomains;
        private readonly ILog _log = LogManager.GetLogger(typeof(AdminAuthenticationProvider));


        /// <summary>
        /// Provider for authenticating admins
        /// </summary>
        /// <param name="context"></param>
        public AdminAuthenticationProvider(FlexinetsContext context, IConfiguration configuration)
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
            if (admin != null)
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


        /// <summary>
        /// Begin password reset
        /// </summary>
        /// <param name="email"></param>
        /// <param name="ipaddress"></param>
        /// <param name="resetBaseUrl"></param>
        /// <returns></returns>
        public async Task BeginResetAsync(String email, String ipaddress, String resetBaseUrl)
        {
            if (!_resetReturnDomains.Contains(resetBaseUrl))
            {
                _log.Warn($"Invalid resetbaseurl {resetBaseUrl} in password reset request. Email: {email}, Ip: {ipaddress}");
                return;
            }

            try
            {
                var admin = await _context.Admins.SingleOrDefaultAsync(o => o.Email == email && o.Status == 1);
                if (admin != null)
                {
                    var reset = new AdminReset
                    {
                        Validto = DateTime.UtcNow.AddDays(2),
                        Id = CryptoMethods.GetRandomString(64),
                        IpaddressRequest = ipaddress
                    };
                    admin.AdminReset.Add(reset);
                    await _context.SaveChangesAsync();

                    // todo move this to servicebus...
                    //using (var message = new MailMessage("portal@flexinets.se", email))
                    //{
                    //    message.Subject = "Flexinets Portal - Password reset";
                    //    message.Bcc.Add("support@flexinets.se");
                    //    message.Body = "To reset your password please follow this link" + Environment.NewLine +
                    //                   Environment.NewLine
                    //                   + resetBaseUrl + reset.id + Environment.NewLine +
                    //                   Environment.NewLine
                    //                   + "If you did not start the reset process, you can ignore this message.";

                    //    await _smtpClient.SendAsync(message);
                    //}
                }
                else
                {
                    _log.Warn($"Failed password reset for {email}");
                }
            }
            catch (Exception ex)
            {
                _log.Error($"Failed password reset for {email}", ex);
            }
        }


        /// <summary>
        /// Complete the password reset
        /// </summary>
        /// <param name="resettoken"></param>
        /// <param name="password"></param>
        /// <param name="ipaddress">IP address of the calling user</param>
        /// <returns>True if successful</returns>
        public async Task<Boolean> CompleteResetAsync(String resettoken, String password, String ipaddress)
        {
            var reset = await _context.AdminReset.Include(o => o.Admin).SingleOrDefaultAsync(o => o.Id == resettoken && DateTime.UtcNow < o.Validto && o.IpaddressReset == null);
            if (reset == null)
            {
                return false;
            }

            var hasher = new PasswordHasher<Admins>();
            reset.Admin.Password = hasher.HashPassword(null, password);
            reset.IpaddressReset = ipaddress;
            await _context.SaveChangesAsync();
            return true;
        }


        /// <summary>
        /// Checks if a reset token is valid
        /// </summary>
        /// <param name="resettoken"></param>
        /// <returns></returns>
        public async Task<Boolean> IsValidResetTokenAsync(String resettoken)
        {
            return await _context.AdminReset.AnyAsync(o => o.Id == resettoken && DateTime.UtcNow < o.Validto && o.IpaddressReset == null);
        }
    }
}
