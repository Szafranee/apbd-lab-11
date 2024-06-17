using System.ComponentModel.DataAnnotations;

namespace Lab_11.Model;

public class Models
{
    public class RefreshTokenRequestModel
    {
        public string RefreshToken { get; set; } = null!;
    }

    public class VerifyPasswordRequestModel
    {
        public string Password { get; set; } = null!;
        public string Hash { get; set; } = null!;
    }

    public class LoginRequestModel
    {
        [Required]
        public string UserName { get; set; } = null!;
        [Required]
        public string Password { get; set; } = null!;
    }

    public class LoginResponseModel
    {
        public string Token { get; set; } = null!;
        public string RefreshToken { get; set; } = null!;
    }

    public class User
    {
        public string Name { get; set; } = null!;
        public string Password { get; set; } = null!;
    }
}