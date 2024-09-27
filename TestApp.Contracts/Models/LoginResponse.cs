namespace TestApp.Contracts.Models;
public class LoginResponse
{
    public required string JwtToken { get; set; }
    public required string RefreshToken { get; set; }
}
