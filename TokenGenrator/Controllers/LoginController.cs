using Nest;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using TokenGenrator.Models;

namespace TokenGenrator.Controllers
{
    public class LoginController : Controller
    {

        //GET: Login
        public ActionResult Index()
        {
            return View();
        }


        [HttpPost]
        [AllowAnonymous] // This attribute allows unauthenticated (anonymous) access to this action.
        [ValidateAntiForgeryToken]
        public ActionResult Index(AccountLoginModel viewModel)
        {
            try
            {
                if (!ModelState.IsValid)
                    return View("Index", viewModel);

// user Authentication
                string encryptedPwd = viewModel.Password;
                var userPassword = Convert.ToString(ConfigurationManager.AppSettings["config:Password"]);
                var userName = Convert.ToString(ConfigurationManager.AppSettings["config:UserName"]);


                if (encryptedPwd.Equals(userPassword) && viewModel.Email.Equals(userName))
                {
                    var roles = new string[] { "SuperAdmin", "Admin" };
                    var jwtSecurityToken = Models.Authentication.GenerateJwtToken(userName, roles.ToList());
                    Session["LoginedIn"] = userName;
                    var validUserName = Models.Authentication.ValidateToken(jwtSecurityToken);
                    return RedirectToAction("Index", "Home", new { token = jwtSecurityToken });

                }

                ModelState.AddModelError("", "Invalid username or password.");

            }
            catch (Exception)
            {
                ModelState.AddModelError("", "Invalid username or password.");
            }
            return View("Index", viewModel);
        }

    }
}