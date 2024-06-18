using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Text;
using Lab_11.Contexts;
using Lab_11.DbModels;
using Lab_11.Model;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

namespace Lab_11.Services;


public interface IAuthService
{
    Task<Models.LoginResponseModel> LoginAsync(Models.LoginRequestModel model);
    Task<Models.LoginResponseModel> RefreshTokenAsync(string refreshToken);
    Task<bool> RegisterAsync(Models.RegisterRequestModel model);
}


public class AuthService (IConfiguration config, DatabaseContext databaseContext) : IAuthService
{
    public async Task<Models.LoginResponseModel> LoginAsync(Models.LoginRequestModel model)
    {
        var user = await databaseContext.Users.FirstOrDefaultAsync(u => u.Name == model.UserName);
        if (user != null && VerifyPassword(user.PasswordHash, model.Password, user.Salt))
        {
            var token = GenerateJwtToken(user);
            var refreshToken = GenerateRefreshToken();

            databaseContext.RefreshTokens.Add(new RefreshToken
            {
                Token = refreshToken,
                ExpiryDate = DateTime.Now.AddDays(3),
                UserId = user.Id
            });
            await databaseContext.SaveChangesAsync();

            return new Models.LoginResponseModel
            {
                Token = token,
                RefreshToken = refreshToken
            };
        }

        return new Models.LoginResponseModel();
    }

    public async Task<Models.LoginResponseModel> RefreshTokenAsync(string refreshToken)
    {
        var storedToken = await databaseContext.RefreshTokens.Include(rt => rt.User)
            .SingleOrDefaultAsync(rt => rt.Token == refreshToken);

        if (storedToken == null || storedToken.ExpiryDate <= DateTime.Now) return null;

        var user = storedToken.User;
        var newJwtToken = GenerateJwtToken(user);
        var newRefreshToken = GenerateRefreshToken();

        storedToken.Token = newRefreshToken;
        storedToken.ExpiryDate = DateTime.Now.AddDays(3);
        databaseContext.RefreshTokens.Update(storedToken);
        await databaseContext.SaveChangesAsync();

        return new Models.LoginResponseModel
        {
            Token = newJwtToken,
            RefreshToken = newRefreshToken
        };

    }

    public async Task<bool> RegisterAsync(Models.RegisterRequestModel model)
    {
        if (await databaseContext.Users.AnyAsync(u => u.Name == model.UserName))
        {
            return false;
        }

        var (hashedPassword, salt) = HashPassword(model.Password);

        var user = new User
        {
            Name = model.UserName,
            Email = model.UserName,
            PasswordHash = hashedPassword,
            Salt = salt
        };

        databaseContext.Users.Add(user);
        await databaseContext.SaveChangesAsync();
        return true;
    }

    private string GenerateJwtToken(User user)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var tokenDescription = new SecurityTokenDescriptor
        {
            Issuer = config["JWT:Issuer"],
            Audience = config["JWT:Audience"],
            Expires = DateTime.UtcNow.AddMinutes(15),
            SigningCredentials = new SigningCredentials(
                new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config["JWT:Key"]!)),
                SecurityAlgorithms.HmacSha256
            )
        };
        var token = tokenHandler.CreateToken(tokenDescription);
        var stringToken = tokenHandler.WriteToken(token);

        return stringToken;
    }

    private string GenerateRefreshToken()
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var refTokenDescription = new SecurityTokenDescriptor
        {
            Issuer = config["JWT:RefIssuer"],
            Audience = config["JWT:RefAudience"],
            Expires = DateTime.UtcNow.AddDays(3),
            SigningCredentials = new SigningCredentials(
                new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config["JWT:RefKey"]!)),
                SecurityAlgorithms.HmacSha256
            )
        };
        var refToken = tokenHandler.CreateToken(refTokenDescription);
        var stringRefToken = tokenHandler.WriteToken(refToken);

        return stringRefToken;
    }

    private static bool VerifyPassword(string storedHash, string password, string storedSalt)
    {
        var salt = Convert.FromBase64String(storedSalt);

        var hashed = Convert.ToBase64String(KeyDerivation.Pbkdf2(
            password: password,
            salt: salt,
            prf: KeyDerivationPrf.HMACSHA1,
            iterationCount: 10000,
            numBytesRequested: 256 / 8
        ));

        return hashed == storedHash;
    }

    private static Tuple<string, string> HashPassword(string password)
    {
        var salt = new byte[128 / 8];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(salt);
        }

        var hashed = Convert.ToBase64String(KeyDerivation.Pbkdf2(
            password: password,
            salt: salt,
            prf: KeyDerivationPrf.HMACSHA1,
            iterationCount: 10000,
            numBytesRequested: 256 / 8
        ));

        var saltBase64 = Convert.ToBase64String(salt);

        return new Tuple<string, string>(hashed, saltBase64);
    }
}