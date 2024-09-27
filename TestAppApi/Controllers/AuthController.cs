
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using TestApp.Contracts.Models;
using TestApp.Contracts.Requests;

namespace TestAppApi.Controllers;

[ApiController]
public class AuthController : ControllerBase
{
    private readonly IConfiguration _configuration;

    public AuthController(IConfiguration configuration)
    {
        _configuration = configuration;
    }
    public async Task<IActionResult> Login([FromBody] LoginRequest request, CancellationToken token)
    {
        User? user = null;

        // Local login first
        user = UserStorage.Users.FirstOrDefault(x => x.Username == request.Username);

        // Just for demo purposes. In reality here is a real PashwordHasher being used
        if (user is null || user.Password != request.Password)
        {
            return Unauthorized();
        }

        // User is authenticated. Generate JWT-Token
        var jwtToken = GenerateJwtToken(user);
        var refreshToken = GenerateRefreshToken(user);

        var response = new LoginResponse
        {
            JwtToken = jwtToken,
            RefreshToken = refreshToken
        };

        return Ok(response);
    }

    private string GenerateJwtToken(User user)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.UTF8.GetBytes(_configuration["JwtOptions:Key"]!);

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()), // TODO: This GUID should be saved in database with user_id
            new("user_id", user.UserId.ToString())
        };

        // Claims would be specified here
       
        int tokenLifeTime = _configuration.GetValue<int>("JwtOptions:TokenLifetime");
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.UtcNow.Add(TimeSpan.FromHours(tokenLifeTime)),
            Issuer = _configuration["JwtOptions:Issuer"]!,
            Audience = _configuration["JwtOptions:Audience"]!,
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
        };

        var token = tokenHandler.CreateToken(tokenDescriptor);

        var jwt = tokenHandler.WriteToken(token);

        return jwt;
    }

    private string GenerateRefreshToken(User user)
    {
        var randomNumber = new byte[32]; // 258 bits 32 * 8 bits
        RandomNumberGenerator.Fill(randomNumber);
        var refreshToken = Convert.ToBase64String(randomNumber);
        return refreshToken;
    }
}
