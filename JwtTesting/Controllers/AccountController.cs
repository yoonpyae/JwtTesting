using System.Security.Cryptography;
using System.Text;
using dotNetProject.Models;
using JwtTesting.Entities;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace JwtTesting.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController(UserManager<IdentityUser> userManager) : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager=userManager;

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterDto model)
        {
            if (await _userManager.Users.AnyAsync(u => u.Email == model.Email))
            {
                return BadRequest("User with this email already exists.");
            }

            // Hash the password
            var hashedPassword = HashPassword(model.Password);

            var user = new IdentityUser
            {
                UserName = model.Username,
                Email = model.Email,
                PasswordHash = hashedPassword
            };

            var result = await _userManager.CreateAsync(user, model.Password);

            if (result.Succeeded)
            {
                return Ok("User registered successfully.");
            }

            return BadRequest(result.Errors);
        }

        private static string HashPassword(string password)
        {
            byte[] bytes = SHA256.HashData(Encoding.UTF8.GetBytes(password));
            return Convert.ToBase64String(bytes);
        }
    }

}

