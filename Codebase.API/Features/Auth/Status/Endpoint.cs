using System;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using Codebase.Application.Interfaces;
using Microsoft.IdentityModel.Tokens;

namespace Codebase.API.Features.Auth.Status;

public class Endpoint: EndpointWithoutRequest<Response>
{
    private IAuthService _authService;
    public Endpoint(IAuthService authService)
    {
        _authService = authService;
    }

    public override void Configure()
    {
        AllowAnonymous();
        Get("auth/status");
    }

    public override async Task HandleAsync(CancellationToken ct)
    {
        HttpContext.Request.Cookies.TryGetValue("Authorization", out var authToken);
        var token = authToken?.Substring("Bearer_".Length).Trim();

        if (string.IsNullOrEmpty(token))
        {
            ThrowError("Jwt token is not found!");
            return;
        }

        var handler = new JwtSecurityTokenHandler();

        var validationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(AppSetting.SigningKey)),
            ValidateIssuer = false,
            ValidateAudience = false,
            ClockSkew = TimeSpan.Zero 
        };

        try
        {
            var principal = handler.ValidateToken(token, validationParameters, out var validatedToken);
            var claims = principal.Claims.ToDictionary(c => c.Type, c => c.Value);

            await SendAsync(
                new Response {
                    IsAuthenticated=true,
                    Email=claims["Email"],
                }, 
                cancellation: ct
            );
        }
        catch (SecurityTokenException)
        {
            ThrowError("Token is invalid or already expired");
        }
    }
}