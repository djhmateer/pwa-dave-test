using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Configuration;
//using PasswordPostgres.Web;
//using Serilog;

namespace PWADaveTest.Pages.Account
{
    public class LoginModel : PageModel
    {
        [BindProperty]
        public InputModel? Input { get; set; }
        public string? ReturnUrl { get; set; }

        [TempData]
        public string? ErrorMessage { get; set; }

        public class InputModel
        {
            [Required]
            [EmailAddress]
            public string Email { get; set; }

            [Required]
            [DataType(DataType.Password)]
            public string Password { get; set; }

            [Display(Name = "Remember me?")]
            public bool RememberMe { get; set; }
        }

        public async Task OnGetAsync(string? returnUrl = null)
        {
            //Log.Information(returnUrl);
            if (!string.IsNullOrEmpty(ErrorMessage))
            {
                ModelState.AddModelError(string.Empty, ErrorMessage);
            }

            // Clear the existing external cookie
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

            ReturnUrl = returnUrl;
        }

        public async Task<IActionResult> OnPostAsync(string? returnUrl = null)
        {
            ReturnUrl = returnUrl;

            if (ModelState.IsValid)
            {
                var user = await AuthenticateUser(Input.Email, Input.Password);

                if (user == null)
                {
                    ModelState.AddModelError(string.Empty, "Invalid login attempt.");
                    return Page();
                }

                var claims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.Email),
                    //new Claim("FullName", user.FullName),
                    new Claim(ClaimTypes.Role,  user.CDRole)
                };

                var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);

                //Log.Information($@"CDRole: {user.CDRole}");
                //Log.Information($@"Remember me: {Input.RememberMe}");

                var authProperties = new AuthenticationProperties
                {
                    //AllowRefresh = <bool>,
                    // Refreshing the authentication session should be allowed.

                    //ExpiresUtc = DateTimeOffset.UtcNow.AddMinutes(10),
                    // The time at which the authentication ticket expires. A 
                    // value set here overrides the ExpireTimeSpan option of 
                    // CookieAuthenticationOptions set with AddCookie.

                    IsPersistent = Input.RememberMe, // false is default
                    //IsPersistent = true,
                    // Whether the authentication session is persisted across 
                    // multiple requests. When used with cookies, controls
                    // whether the cookie's lifetime is absolute (matching the
                    // lifetime of the authentication ticket) or session-based.

                    //IssuedUtc = <DateTimeOffset>,
                    // The time at which the authentication ticket was issued.

                    //RedirectUri = <string>
                    // The full path or absolute URI to be used as an http 
                    // redirect response value.
                };

                await HttpContext.SignInAsync(
                    CookieAuthenticationDefaults.AuthenticationScheme,
                    new ClaimsPrincipal(claimsIdentity),
                    authProperties);

                //Log.Information($"User {user.Email} CDRole: {user.CDRole} logged in at {DateTime.UtcNow}");

                // creates a 302 Found which then redirects to the resource
                return LocalRedirect(returnUrl ?? "/");
            }

            // Something failed. Redisplay the form.
            return Page();
        }


        public class Model
        {
            public string Email { get; set; }
            //public string FullName { get; set; }
            //public bool IsAdmin { get; set; }
            public string CDRole { get; set; }
        }

        public static class CDRole
        {
            public const string Tier1 = "Tier1";
            public const string Tier2 = "Tier2";
            public const string Admin = "Admin";
        }



        private async Task<Model?> AuthenticateUser(string email, string password)
        {
            await Task.Delay(500);

            if (email == "tier1@contoso.com")
            {
                return new Model
                {
                    Email = "tier1@contoso.com",
                    CDRole = CDRole.Tier1
                };
            }

            if (email == "tier2@contoso.com")
            {
                return new Model
                {
                    Email = "tier2@contoso.com",
                    CDRole = CDRole.Tier2
                };
            }

            if (email == "admin@contoso.com")
            {
                return new Model
                {
                    Email = "admin@contoso.com",
                    CDRole = CDRole.Admin
                };
            }

            return null;
        }
    }
}
