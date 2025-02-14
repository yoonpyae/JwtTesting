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
    public class AccountController(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager, IConfiguration config, ILogger<AccountController> logger) : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager = userManager;
        private readonly SignInManager<IdentityUser> _signInManager = signInManager;
        private readonly IConfiguration _config = config;
        private readonly ILogger<AccountController> _logger = logger;

        [HttpPost("register")]
        [AllowAnonymous] // ✅ Allow users to register without authentication
        public async Task<IActionResult> Register([FromBody] RegisterDto model)
        {
            _logger.LogInformation("Registering user with email: {Email}", model.Email);

            if (await _userManager.Users.AnyAsync(u => u.Email == model.Email))
            {
                _logger.LogWarning("User with email {Email} already exists", model.Email);

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
                _logger.LogError("Failed to create user with email {Email}", model.Email);

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


            _logger.LogInformation("User with email {Email} registered successfully", model.Email);
            return Ok("User registered successfully.");
        }

        [HttpGet("admin")]
        [Authorize(Roles = "Admin")]
        public IActionResult AdminAction()
        {
            _logger.LogInformation("Admin action accessed");
            return Ok("This is an admin-only action.");
        }

        [HttpGet("user")]
        [Authorize(Roles = "User")]
        public IActionResult UserAction()
        {
            _logger.LogInformation("User action accessed");

            return Ok("This is a user-only action.");
        }

        [HttpPost("login")]
        [AllowAnonymous] // ✅ Allow users to log in without authentication
        public async Task<IActionResult> Login([FromBody] LoginDto model)
        {
            _logger.LogInformation("User login attempt with identifier: {Identifier}", model.UsernameOrEmailOrPhone);

            // Check if the identifier is email, username, or phone number
            IdentityUser? user = null;

            // Check for email
            if (model.UsernameOrEmailOrPhone.Contains('@'))
            {
                user = await _userManager.FindByEmailAsync(model.UsernameOrEmailOrPhone);
            }
            // Check for phone number (assuming it's a valid phone number format)
            else
            {
                user = model.UsernameOrEmailOrPhone.Length >= 10
                    ? await _userManager.Users.FirstOrDefaultAsync(u => u.PhoneNumber == model.UsernameOrEmailOrPhone)
                    : await _userManager.FindByNameAsync(model.UsernameOrEmailOrPhone);
            }

            if (user == null)
            {
                _logger.LogWarning("Invalid login attempt with identifier: {Identifier}", model.UsernameOrEmailOrPhone);
                return Unauthorized("Invalid username, email, or phone number.");
            }

            if (await _userManager.IsLockedOutAsync(user))
            {
                _logger.LogWarning("User account is locked out for identifier: {Identifier}", model.UsernameOrEmailOrPhone);
                return Unauthorized("User account is locked out.");
            }

            Microsoft.AspNetCore.Identity.SignInResult result = await _signInManager.PasswordSignInAsync(user, model.Password, false, false);
            if (!result.Succeeded)
            {
                _ = await _userManager.AccessFailedAsync(user);

                if (await _userManager.GetAccessFailedCountAsync(user) >= 3)
                {
                    _ = await _userManager.SetLockoutEnabledAsync(user, true);
                    _ = await _userManager.SetLockoutEndDateAsync(user, DateTimeOffset.UtcNow.AddMinutes(5));
                }
                _logger.LogWarning("Invalid login attempt with identifier: {Identifier}", model.UsernameOrEmailOrPhone);

                return Unauthorized("Invalid email or password.");
            }

            _ = await _userManager.ResetAccessFailedCountAsync(user);

            (string token, string refreshToken, DateTime refreshTokenExpiry) = await GenerateJwtToken(user);
            _logger.LogInformation("User with identifier {Identifier} logged in successfully", model.UsernameOrEmailOrPhone);
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
                expires: DateTime.UtcNow.AddMinutes(2), // Access token expires in 1 minute
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
            _logger.LogInformation("Token refresh attempt");

            if (tokenRequest == null || string.IsNullOrEmpty(tokenRequest.RefreshToken) || string.IsNullOrEmpty(tokenRequest.AccessToken))
            {
                _logger.LogWarning("Invalid token refresh request: Missing tokens");

                return BadRequest("Invalid client request: Missing tokens.");
            }

            ClaimsPrincipal? principal = GetPrincipalFromExpiredToken(tokenRequest.AccessToken);
            if (principal == null)
            {
                _logger.LogWarning("Invalid token refresh request: Could not extract claims");

                return BadRequest("Invalid client request: Could not extract claims.");
            }

            string? userId = principal.FindFirst(ClaimTypes.NameIdentifier)?.Value; // FIXED: Use NameIdentifier claim
            if (userId == null)
            {
                _logger.LogWarning("Invalid token refresh request: User ID missing");

                return BadRequest("Invalid client request: User ID missing.");
            }

            IdentityUser? user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                _logger.LogWarning("Invalid token refresh request: User not found");

                return BadRequest("Invalid client request: User not found.");
            }

            if (!await ValidateRefreshToken(user, tokenRequest.RefreshToken))
            {
                _logger.LogWarning("Invalid token refresh request: Refresh token invalid or expired");

                return BadRequest("Invalid client request: Refresh token invalid or expired.");
            }

            // Generate new tokens
            (string newAccessToken, string newRefreshToken, DateTime newRefreshTokenExpiry) = await GenerateJwtToken(user);

            _logger.LogInformation("Token refresh successful");
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
                    _logger.LogWarning("Invalid token");

                    return null; // Invalid token
                }

                // ✅ Check if the token is expired
                Claim? expiryClaim = principal.FindFirst(JwtRegisteredClaimNames.Exp);
                if (expiryClaim != null && long.TryParse(expiryClaim.Value, out long expiry))
                {
                    DateTime expiryDate = DateTimeOffset.FromUnixTimeSeconds(expiry).UtcDateTime;
                    if (expiryDate > DateTime.UtcNow)
                    {
                        _logger.LogInformation("Token is still valid, no need to refresh");

                        return null; // Token is still valid, no need to refresh
                    }
                }

                return principal;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error validating token");

                return null;
            }
        }


        private async Task<bool> ValidateRefreshToken(IdentityUser user, string refreshToken)
        {
            string? storedRefreshToken = await _userManager.GetAuthenticationTokenAsync(user, "MyApp", "RefreshToken");
            string? storedRefreshTokenExpiry = await _userManager.GetAuthenticationTokenAsync(user, "MyApp", "RefreshTokenExpiry");

            if (string.IsNullOrEmpty(storedRefreshToken) || string.IsNullOrEmpty(storedRefreshTokenExpiry))
            {
                _logger.LogWarning("Stored refresh token or expiry is missing");

                return false;
            }

            // ✅ Ensure refresh token is not expired
            if (!DateTime.TryParse(storedRefreshTokenExpiry, out DateTime expiryDate) || expiryDate < DateTime.UtcNow)
            {
                _logger.LogWarning("Refresh token is expired");

                return false; // Expired
            }

            return storedRefreshToken == refreshToken;
        }

        [HttpGet("generate-reset-token")]
        public async Task<IActionResult> GenerateResetToken([FromQuery] string email)
        {
            // Find the user by email
            IdentityUser? user = await _userManager.FindByEmailAsync(email);
            if (user == null)
            {
                return BadRequest(new { Message = "User not found" });
            }

            // Generate the password reset token
            string token = await _userManager.GeneratePasswordResetTokenAsync(user);

            // Return the token in the response (don't send it via email)
            return Ok(new { Token = token });
        }


        [HttpPost("reset-password")]
        [AllowAnonymous]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordDto model)
        {
            _logger.LogInformation("Resetting password for email: {Email}", model.Email);

            IdentityUser? user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
            {
                _logger.LogWarning("User with email {Email} not found", model.Email);
                return BadRequest(new { message = "User not found" });
            }

            IdentityResult result = await _userManager.ResetPasswordAsync(user, model.Token, model.NewPassword);
            if (!result.Succeeded)
            {
                _logger.LogError("Failed to reset password for email {Email}", model.Email);
                return BadRequest(new { message = "Failed to reset password", errors = result.Errors });
            }

            _logger.LogInformation("Password successfully reset for email: {Email}", model.Email);
            return Ok(new { message = "Password reset successful" });
        }


    }
}
