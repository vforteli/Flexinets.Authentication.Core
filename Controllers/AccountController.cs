using Flexinets.Core.Database.Models;
using Flexinets.Portal.Models;
using Flexinets.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System;
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
        public async Task<IActionResult> Get()
        {
            var adminId = Convert.ToInt32(User.Identity.Name);
            var admin = await _context.Admins.Include(o => o.Roles).SingleOrDefaultAsync(o => o.AdminId == adminId);

            return Ok(new AdminModel
            {
                AdminID = admin.AdminId,
                EmailAddress = admin.Email,
                Fullname = $"{ admin.Firstname} {admin.Lastname}",
                Phonenumber = admin.Phonenumber,
                Roles = admin.Roles.Select(o => ((RoleTypes)o.RoleId).ToString()).ToList()
            });
        }


        //[ValidateModelStateFilter]
        //[HttpPost("api/account/")]
        //public async Task<IActionResult> Post([FromBody]AdminModel model)
        //{
        //    try
        //    {
        //        var admin = await _adminRepository.GetAdminAsync(User.Identity.GetUserId<Int32>(), false);
        //        if (model.Fullname != null && model.Fullname.IndexOf(" ") > 0)
        //        {
        //            admin.Firstname = model.Fullname.Substring(0, model.Fullname.LastIndexOf(" ")).Trim();
        //            admin.Lastname = model.Fullname.Substring(model.Fullname.LastIndexOf(" ")).Trim();
        //        }
        //        else
        //        {
        //            admin.Firstname = "";
        //            admin.Lastname = model.Fullname ?? "";
        //        }
        //        admin.EmailAddress = model.EmailAddress;
        //        admin.Phonenumber = Phonenumber.Parse(model.Phonenumber);
        //        await _adminRepository.SaveAdminAsync(admin);
        //        return Ok();
        //    }
        //    catch (UpdateException ex)
        //    {
        //        if (!ex.InnerException.Message.Contains("Unique"))
        //            throw;

        //        ModelState.AddModelError("EmailAddress", "This email address is already registered");
        //        return BadRequest(ModelState);
        //    }
        //}


        //[ValidateModelStateFilter]
        //[HttpPost("api/account/changepassword/")]
        //public async Task<IActionResult> ChangePassword([FromBody]ChangePasswordModel model)
        //{
        //    var userid = Convert.ToInt32(User.Identity.Name);
        //    var admin = await _adminRepository.GetAdminAsync(User.Identity.GetUserId<Int32>(), false);
        //    if (await _adminAuthenticationProvider.AuthenticateAsync(admin.Username ?? admin.EmailAddress, model.OldPassword).GetValueOrDefault(0) == userid)
        //    {
        //        admin.SetPassword(model.Password);
        //        admin.MustChangePassword = false;
        //        await _adminRepository.SaveAdminAsync(admin);
        //        return Ok();
        //    }

        //    return BadRequest("Invalid credentials");
        //}


        //[ValidateModelStateFilter]
        //[HttpPost("api/account/setpassword/")]
        //[AllowAnonymous]
        //public async Task<IActionResult> SetPassword([FromBody]SetPasswordModel model)
        //{
        //    var adminId = _adminManager.Authenticate(model.EmailAddress, model.OldPassword);
        //    if (adminId.HasValue)
        //    {
        //        var admin = await _adminRepository.GetAdminAsync(adminId.Value, false);
        //        admin.SetPassword(model.Password);
        //        admin.MustChangePassword = false;
        //        await _adminRepository.SaveAdminAsync(admin);
        //        return Ok();
        //    }

        //    return BadRequest("Invalid credentials");
        //}


        //[ValidateModelStateFilter]
        //[HttpPost("api/account/resetpassword/beginreset/")]
        //[AllowAnonymous]
        //public async Task<IActionResult> Post(ResetModel model)
        //{
        //    try
        //    {
        //        await _adminManager.BeginResetAsync(model.EmailAddress, HttpContext.Current.Request.UserHostAddress, CloudConfigurationManager.GetSetting("ResetAdminUrl"));
        //    }
        //    catch (Exception ex)
        //    {
        //        _log.Error("Reset begin failed", ex);
        //    }
        //    return Ok();
        //}


        //[HttpGet("api/account/resetpassword/validateresettoken/{id}")]
        //[AllowAnonymous]
        //public async Task<IActionResult> Get(String id)
        //{
        //    return Ok(await _adminManager.IsValidResetTokenAsync(id));
        //}


        //[HttpPost("api/account/resetpassword/completereset/")]
        //[ValidateModelStateFilter]
        //[AllowAnonymous]
        //public async Task<IActionResult> Post(ResetPasswordModel model)
        //{
        //    return Ok(await _adminManager.CompleteResetAsync(model.ResetId, model.Password, HttpContext.Current.Request.UserHostAddress));
        //}


        [HttpGet("api/checkemailavailability")]
        [AllowAnonymous]
        public async Task<IActionResult> CheckEmailAvailability(String email)
        {
            var exists = await _context.Admins.AnyAsync(o => o.Email == email);
            return Ok(new { available = !exists, email = email });
        }
    }
}