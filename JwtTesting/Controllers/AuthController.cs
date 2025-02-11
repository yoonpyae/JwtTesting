using dotNetProject.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace JwtTesting.Controllers
{
    
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        [HttpGet("status")]
        [Authorize]
        public IActionResult GetStatus()
        {
            return Ok(new { message = "Authorized" });
        }

    }
}
