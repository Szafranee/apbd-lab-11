using Lab_11.Model;
using Lab_11.Services;
using Microsoft.AspNetCore.Mvc;

namespace Lab_11.Controllers;

[Route("api/[controller]")]
[ApiController]
public class AuthController(IAuthService authService) : ControllerBase
{
    [HttpPost("login")]
    public async Task<IActionResult> Login(Models.LoginRequestModel loginRequestModel)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        var response = await authService.LoginAsync(loginRequestModel);
        if (response is { RefreshToken: not null, Token: not null })
        {
            return Ok(response);
        }
        return Unauthorized("Wrong username or password");
    }

    [HttpPost("refresh")]
    public async Task<IActionResult> RefreshToken(Models.RefreshTokenRequestModel refreshTokenRequestModel)
    {
        var response = await authService.RefreshTokenAsync(refreshTokenRequestModel.RefreshToken);
        if (response is { RefreshToken: not null, Token: not null })
        {
            return Ok(response);
        }
        return Unauthorized("Invalid token");
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register(Models.RegisterRequestModel registerRequestModel)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        var success = await authService.RegisterAsync(registerRequestModel);
        if (success)
        {
            return Ok("User registered successfully");
        }
        return BadRequest("Username already exists");
    }
}