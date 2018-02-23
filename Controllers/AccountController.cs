using Flexinets.Common;
using Flexinets.Core.Database.Models;
using Flexinets.Portal.Models;
using Flexinets.Security.Core;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System;
using System.Data.SqlClient;
using System.Linq;
using System.Threading.Tasks;

namespace FlexinetsAuthentication.Core.Controllers
{
    public class AccountController : Controller
    {
        private readonly FlexinetsContext _context;
        private readonly AdminAuthenticationProvider _adminAuthenticationProvider;


        public AccountController(FlexinetsContext context, AdminAuthenticationProvider adminAuthenticationProvider)
        {
            _context = context;
            _adminAuthenticationProvider = adminAuthenticationProvider;
        }


        [HttpGet("api/account/"), Authorize]
        public async Task<IActionResult> GetAccount()
        {
            var admin = await _context.Admins.Include(o => o.Roles).SingleOrDefaultAsync(o => o.AdminId == Convert.ToInt32(User.Identity.Name));

            return Ok(new AdminModel
            {
                AdminID = admin.AdminId,
                EmailAddress = admin.Email,
                Fullname = $"{ admin.Firstname} {admin.Lastname}",
                Phonenumber = admin.Phonenumber,
                Roles = admin.Roles.Select(o => ((RoleTypes)o.RoleId).ToString()).ToList()
            });
        }


        [ValidateModelStateFilter]
        [HttpPost("api/account/")]
        public async Task<IActionResult> UpdateAccount([FromBody]AdminModel model)
        {
            try
            {
                var (firstname, lastname) = Utils.SplitFullname(model.Fullname);
                var admin = await _context.Admins.SingleOrDefaultAsync(o => o.AdminId == Convert.ToInt32(User.Identity.Name));
                admin.Firstname = firstname;
                admin.Lastname = lastname;
                admin.Email = model.EmailAddress;
                admin.Phonenumber = Phonenumber.Parse(model.Phonenumber);
                await _context.SaveChangesAsync();
                return Ok(admin.AdminId);
            }
            catch (DbUpdateException ex) when (ex.InnerException is SqlException sqlEx && (sqlEx.Number == 2601 || sqlEx.Number == 2627))
            {
                ModelState.AddModelError("EmailAddress", "This email address is already registered");
                return BadRequest(ModelState);
            }
        }


        [ValidateModelStateFilter]
        [HttpPost("api/account/changepassword/")]
        public async Task<IActionResult> ChangePassword([FromBody]ChangePasswordModel model)
        {
            var admin = await _context.Admins.SingleOrDefaultAsync(o => o.AdminId == Convert.ToInt32(User.Identity.Name));
            if ((await _adminAuthenticationProvider.AuthenticateAsync(admin.Username ?? admin.Email, model.OldPassword))?.AdminId == admin.AdminId)
            {
                admin.Password = CryptoMethods.HashPassword(model.Password);
                admin.Mustchangepassword = false;
                await _context.SaveChangesAsync();
                return Ok(admin.AdminId);
            }

            return BadRequest("Invalid credentials");
        }


        [ValidateModelStateFilter]
        [HttpPost("api/account/resetpassword/beginreset/")]
        [AllowAnonymous]
        public async Task<IActionResult> BeginReset(ResetModel model)
        {
            await _adminAuthenticationProvider.BeginResetAsync(model.EmailAddress, HttpContext.Connection.RemoteIpAddress.ToString(), model.ReturnUrl);
            return Ok();
        }


        [HttpGet("api/account/resetpassword/validateresettoken/{id}")]
        [AllowAnonymous]
        public async Task<IActionResult> ValidateResetToken(String id)
        {
            return Ok(await _adminAuthenticationProvider.IsValidResetTokenAsync(id));
        }


        [HttpPost("api/account/resetpassword/completereset/")]
        [ValidateModelStateFilter]
        [AllowAnonymous]
        public async Task<IActionResult> CompleteReset(ResetPasswordModel model)
        {
            return Ok(await _adminAuthenticationProvider.CompleteResetAsync(model.ResetId, model.Password, HttpContext.Connection.RemoteIpAddress.ToString()));
        }


        [HttpGet("api/checkemailavailability")]
        [AllowAnonymous]
        public async Task<IActionResult> CheckEmailAvailability(String email)
        {
            var exists = await _context.Admins.AnyAsync(o => o.Email == email);
            return Ok(new { available = !exists, email = email });
        }
    }
}