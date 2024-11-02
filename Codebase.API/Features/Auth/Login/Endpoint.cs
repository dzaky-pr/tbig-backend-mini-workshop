using System;
using Codebase.Application.Interfaces;
using FastEndpoints.Security;

namespace Codebase.API.Features.Auth.Login;

public class Endpoint : Endpoint<Request>
{
    private IAuthService _authService;
    public Endpoint(IAuthService authService)
    {
        _authService = authService;
    }

    public override void Configure()
    {
        Post("/auth/login");
        AllowAnonymous();
    }

    public override async Task HandleAsync(Request req, CancellationToken ct)
    {
        var login = _authService.Login(req.Email, req.Password);
        if (login.IsValid)
        {
            var jwtToken = JwtBearer.CreateToken(
                o =>
                {
                    o.SigningKey = AppSetting.SigningKey;
                    o.ExpireAt = DateTime.UtcNow.AddMinutes(AppSetting.ExpirationMinutes);
                    o.User.Claims.Add(("Email", req.Email));
                });

            var token = $"Bearer_{jwtToken}";

            HttpContext.Response.Cookies.Append("Authorization", token, new CookieOptions
                {
                    HttpOnly = true,         
                    Secure = false,           
                    SameSite = SameSiteMode.Lax,
                    Expires = DateTime.UtcNow.AddMinutes(AppSetting.ExpirationMinutes)
                });

            await SendAsync(
                new {
                    req.Email,
                    Token = token
                });
        }
        else
            ThrowError("The supplied credentials are invalid!");
    }
}