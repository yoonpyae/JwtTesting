using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using dotNetProject.Models;
using JwtTesting.Entities;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

namespace JwtTesting.Controllers
{
    [Authorize]
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager, IConfiguration config) : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager = userManager;
        private readonly SignInManager<IdentityUser> _signInManager = signInManager;
        private readonly IConfiguration _config = config;

        [HttpPost("register")]
        [AllowAnonymous] // ✅ Allow users to register without authentication
        public async Task<IActionResult> Register([FromBody] RegisterDto model)
        {
            if (await _userManager.Users.AnyAsync(u => u.Email == model.Email))
            {
                return BadRequest(new DefaultResponseModel()
                {
                    Success = false,
                    StatusCode = StatusCodes.Status400BadRequest,
                    Data = null,
                    Message = "Username already exists"
                });
            }

            IdentityUser user = new()
            {
                UserName = model.Username,
                Email = model.Email,
                LockoutEnabled = true // Enable lockout for new users
            };

            IdentityResult result = await _userManager.CreateAsync(user, model.Password); // ✅ ASP.NET Identity automatically hashes the password

            if (!result.Succeeded)
            {
                return BadRequest(new DefaultResponseModel()
                {
                    Success = false,
                    StatusCode = StatusCodes.Status400BadRequest,
                    Message = "Failed to create user"
                });
            }

            // Assign role to user
            if (!string.IsNullOrEmpty(model.Role))
            {
                _ = await _userManager.AddToRoleAsync(user, model.Role);
            }

            return Ok("User registered successfully.");
        }

        [HttpGet("admin")]
        [Authorize(Roles = "Admin")]
        public IActionResult AdminAction()
        {
            return Ok("This is an admin-only action.");
        }

        [HttpGet("user")]
        [Authorize(Roles = "User")]
        public IActionResult UserAction()
        {
            return Ok("This is a user-only action.");
        }

        [HttpPost("login")]
        [AllowAnonymous] // ✅ Allow users to log in without authentication
        public async Task<IActionResult> Login([FromBody] LoginDto model)
        {
            IdentityUser? user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null || user.UserName == null)
            {
                return Unauthorized("Invalid email or password.");
            }

            if (await _userManager.IsLockedOutAsync(user))
            {
                return Unauthorized("User account is locked out.");
            }

            Microsoft.AspNetCore.Identity.SignInResult result = await _signInManager.PasswordSignInAsync(user.UserName, model.Password, false, false);
            if (!result.Succeeded)
            {
                _ = await _userManager.AccessFailedAsync(user);

                if (await _userManager.GetAccessFailedCountAsync(user) >= 3)
                {
                    _ = await _userManager.SetLockoutEnabledAsync(user, true);
                    _ = await _userManager.SetLockoutEndDateAsync(user, DateTimeOffset.UtcNow.AddMinutes(5));
                }

                return Unauthorized("Invalid email or password.");
            }

            _ = await _userManager.ResetAccessFailedCountAsync(user);

            (string token, string refreshToken, DateTime refreshTokenExpiry) = await GenerateJwtToken(user);
            return Ok(new { token, refreshToken, refreshTokenExpiry });
        }

        private async Task<(string, string, DateTime)> GenerateJwtToken(IdentityUser user)
        {
            IConfigurationSection jwtSettings = _config.GetSection("Jwt");
            SymmetricSecurityKey key = new(Encoding.UTF8.GetBytes(jwtSettings["Key"] ?? throw new InvalidOperationException("JWT Key not found")));
            SigningCredentials creds = new(key, SecurityAlgorithms.HmacSha256);

            List<Claim> claims =
            [
                new Claim(JwtRegisteredClaimNames.Sub, user.Id),
                new Claim(JwtRegisteredClaimNames.Email, user.Email ?? string.Empty),
                new Claim(ClaimTypes.NameIdentifier, user.Id) // ✅ Ensure this is set
            ];

            // Add roles to claims
            IList<string> roles = await _userManager.GetRolesAsync(user);
            claims.AddRange(roles.Select(role => new Claim(ClaimTypes.Role, role)));

            JwtSecurityToken token = new(
                issuer: jwtSettings["Issuer"],
                audience: jwtSettings["Audience"],
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(1), // Access token expires in 1 minute
                signingCredentials: creds
            );

            (string refreshToken, DateTime refreshTokenExpiry) = GenerateRefreshToken();

            // ✅ Always update the refresh token in storage
            _ = await _userManager.SetAuthenticationTokenAsync(user, "MyApp", "RefreshToken", refreshToken);
            _ = await _userManager.SetAuthenticationTokenAsync(user, "MyApp", "RefreshTokenExpiry", refreshTokenExpiry.ToString());

            return (new JwtSecurityTokenHandler().WriteToken(token), refreshToken, refreshTokenExpiry);
        }


        private (string, DateTime) GenerateRefreshToken()
        {
            byte[] randomNumber = new byte[32];
            using RandomNumberGenerator rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);
            string refreshToken = Convert.ToBase64String(randomNumber);
            DateTime refreshTokenExpiry = DateTime.UtcNow.AddMinutes(3); // Set refresh token to expire in 3 minutes
            return (refreshToken, refreshTokenExpiry);
        }

        [HttpPost("refresh")]
        [AllowAnonymous]
        public async Task<IActionResult> Refresh([FromBody] TokenRequestDto tokenRequest)
        {
            if (tokenRequest == null || string.IsNullOrEmpty(tokenRequest.RefreshToken) || string.IsNullOrEmpty(tokenRequest.AccessToken))
            {
                return BadRequest("Invalid client request: Missing tokens.");
            }

            ClaimsPrincipal? principal = GetPrincipalFromExpiredToken(tokenRequest.AccessToken);
            if (principal == null)
            {
                return BadRequest("Invalid client request: Could not extract claims.");
            }

            string? userId = principal.FindFirst(ClaimTypes.NameIdentifier)?.Value; // FIXED: Use NameIdentifier claim
            if (userId == null)
            {
                return BadRequest("Invalid client request: User ID missing.");
            }

            IdentityUser? user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return BadRequest("Invalid client request: User not found.");
            }

            if (!await ValidateRefreshToken(user, tokenRequest.RefreshToken))
            {
                return BadRequest("Invalid client request: Refresh token invalid or expired.");
            }

            // Generate new tokens
            (string newAccessToken, string newRefreshToken, DateTime newRefreshTokenExpiry) = await GenerateJwtToken(user);

            return Ok(new
            {
                AccessToken = newAccessToken,
                RefreshToken = newRefreshToken,
                RefreshTokenExpiry = newRefreshTokenExpiry
            });
        }


        private ClaimsPrincipal? GetPrincipalFromExpiredToken(string token)
        {
            try
            {
                TokenValidationParameters tokenValidationParameters = new()
                {
                    ValidateAudience = false,
                    ValidateIssuer = false,
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"] ?? throw new InvalidOperationException("JWT Key not found"))),
                    ValidateLifetime = false // Allow expired tokens
                };

                JwtSecurityTokenHandler tokenHandler = new();
                ClaimsPrincipal principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out SecurityToken securityToken);

                if (securityToken is not JwtSecurityToken jwtToken || !jwtToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
                {
                    return null; // Invalid token
                }

                // ✅ Check if the token is expired
                Claim? expiryClaim = principal.FindFirst(JwtRegisteredClaimNames.Exp);
                if (expiryClaim != null && long.TryParse(expiryClaim.Value, out long expiry))
                {
                    DateTime expiryDate = DateTimeOffset.FromUnixTimeSeconds(expiry).UtcDateTime;
                    if (expiryDate > DateTime.UtcNow)
                    {
                        return null; // Token is still valid, no need to refresh
                    }
                }

                return principal;
            }
            catch
            {
                return null;
            }
        }


        private async Task<bool> ValidateRefreshToken(IdentityUser user, string refreshToken)
        {
            string? storedRefreshToken = await _userManager.GetAuthenticationTokenAsync(user, "MyApp", "RefreshToken");
            string? storedRefreshTokenExpiry = await _userManager.GetAuthenticationTokenAsync(user, "MyApp", "RefreshTokenExpiry");

            if (string.IsNullOrEmpty(storedRefreshToken) || string.IsNullOrEmpty(storedRefreshTokenExpiry))
            {
                return false;
            }

            // ✅ Ensure refresh token is not expired
            if (!DateTime.TryParse(storedRefreshTokenExpiry, out DateTime expiryDate) || expiryDate < DateTime.UtcNow)
            {
                return false; // Expired
            }

            return storedRefreshToken == refreshToken;
        }

    }
}
