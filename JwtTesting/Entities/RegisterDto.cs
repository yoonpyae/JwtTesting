﻿namespace JwtTesting.Entities
{
    public class RegisterDto
    {
        public string Username { get; set; }
        public string Email { get; set; }
        public string Password { get; set; }
        public string Role { get; set; }  // Add this line for the role

    }


}
