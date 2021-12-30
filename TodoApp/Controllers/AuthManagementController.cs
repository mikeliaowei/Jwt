using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using TodoApp.Configuration;
using TodoApp.Models.DTOs.Responses;
using TodoApp.Models.DTOs.Requests;
using TodoApp.Data;
using TodoApp.Models;
using Microsoft.EntityFrameworkCore;

namespace TodoApp.Controllers
{
	[Route("api/[controller]")]
	[ApiController]
	public class AuthManagementController : ControllerBase
	{
		private readonly UserManager<IdentityUser> _userManager;
		private readonly JwtConfig _jwtConfig;
		private readonly TokenValidationParameters _tokenValidationParameters;
		private readonly ApiDbContext _apiDbContext;

		public AuthManagementController(
			UserManager<IdentityUser> userManager, 
			IOptionsMonitor<JwtConfig> optionsMonitor,
			TokenValidationParameters tokenValidationParameters,
			ApiDbContext apiDbContext)
		{
			_userManager = userManager;
			_jwtConfig = optionsMonitor.CurrentValue;
			_tokenValidationParameters = tokenValidationParameters;
			_apiDbContext = apiDbContext;
		}

		[HttpPost]
		[Route("Register")]
		public async Task<IActionResult> Register([FromBody] UserRegistrationDto user)
		{
			if(ModelState.IsValid)
			{
				//we can utilise the model
				var existingUser = await _userManager.FindByEmailAsync(user.Email);

				if(existingUser != null)
				{
					return BadRequest(new RegistrationResponse()
					{
						Errors = new List<string>() { "Email already in use" },
						Sucess = false
					});
				}

				var newUser = new IdentityUser() { Email = user.Email, UserName = user.Username };
				var isCreated = await _userManager.CreateAsync(newUser, user.Password);

				if(isCreated.Succeeded)
				{
					var jwtToken = await GenerateJwtTokens(newUser);

					return Ok(jwtToken);
				}
				else
				{
					return BadRequest(new RegistrationResponse()
					{
						Errors = isCreated.Errors.Select(x => x.Description).ToList(),
						Sucess = false
					});
				}
			}

			return BadRequest(new RegistrationResponse()
			{
				Errors = new List<string>() { "Invalid payload"},
				Sucess = false
			});
		}

		[HttpPost]
		[Route("Login")]
		public async Task<IActionResult> Login([FromBody] UserLoginRequest user)
		{
			if(ModelState.IsValid)
			{
				var existingUser = await _userManager.FindByEmailAsync(user.Email);

				if(existingUser == null)
				{
					return BadRequest(new RegistrationResponse()
					{
						Errors = new List<string>() { "Invalid login request" },
						Sucess = false
					});
				}

				var isCorrect = await _userManager.CheckPasswordAsync(existingUser, user.Password);

				if(!isCorrect)
				{
					return BadRequest(new RegistrationResponse()
					{
						Errors = new List<string>() { "Invalid login request" },
						Sucess = false
					});
				}

				var jwtToken = await GenerateJwtTokens(existingUser);

				return Ok(jwtToken);
			}

			return BadRequest(new RegistrationResponse()
			{
				Errors = new List<string>() { "Invalid payload" },
				Sucess = false
			});
		}

		[HttpPost]
		[Route("RefreshToken")]
		public async Task<IActionResult> RefreshToken([FromBody] TokenRequest tokenRequest)
		{
			if (ModelState.IsValid)
			{
				var result = await VerifyAndGenerateToken(tokenRequest);

				if(result == null)
				{
					return BadRequest(new RegistrationResponse()
					{
						Errors = new List<string>() { "Invalid tokens" },
						Sucess = false
					});
				}

				return Ok(result);
			}

			return BadRequest(new RegistrationResponse()
			{
				Errors = new List<string>() { "Invalid payload" },
				Sucess = false
			});
		}

		private async Task<AuthResult> VerifyAndGenerateToken(TokenRequest tokenRequest)
		{
			var jwtTokenHandler = new JwtSecurityTokenHandler();

			try
			{
				// Validation 1 - Validate JWT token format
				var tokenInVerification = jwtTokenHandler.ValidateToken(tokenRequest.Token, _tokenValidationParameters, out var validatedToken);
				
				// Validation 2 - validate encryption alg
				if(validatedToken is JwtSecurityToken jwtSecurityToken)
				{
					var result = jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCulture);

					if (result == false)
					{
						return null;
					}
				}

				//Validation 3 - validate expiry date
				var utcExpiryDate = long.Parse(tokenInVerification.Claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Exp).Value);

				var expiryDate = UnixTimeStampToDateTime(utcExpiryDate);

				if(expiryDate > DateTime.UtcNow)
				{
					return new AuthResult()
					{
						Sucess = false,
						Errors = new List<string>() { "Token has not yet expired" },
					};
				}

				//validation 4 - validate existence of token
				var storedToken = await _apiDbContext.RefreshTokens.FirstOrDefaultAsync(x => x.Token == tokenRequest.RefreshToken);

				if(storedToken == null)
				{
					return new AuthResult()
					{
						Sucess = false,
						Errors = new List<string>() { "Token does not exist" },
					};
				}

				//validation 5 - validate if use
				if(storedToken.IsUsed)
				{
					return new AuthResult()
					{
						Sucess = false,
						Errors = new List<string>() { "Token has been used" },
					};
				}

				//validation 6 - validate if revoke
				if(storedToken.IsRevorked)
				{
					return new AuthResult()
					{
						Sucess = false,
						Errors = new List<string>() { "Token has been revoked" },
					};
				}

				//validation 7 - validate the id
				var jti = tokenInVerification.Claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Jti).Value;
				if(storedToken.JwtId != jti)
				{
					return new AuthResult()
					{
						Sucess = false,
						Errors = new List<string>() { "Token doesn't match" },
					};
				}

				// update current token
				storedToken.IsUsed = true;
				_apiDbContext.RefreshTokens.Update(storedToken);
				await _apiDbContext.SaveChangesAsync();

				// Generate a new token
				var dbUser = await _userManager.FindByIdAsync(storedToken.UserId);
				return await GenerateJwtTokens(dbUser);
			}
			catch (Exception ex)
			{
				return null;
			}
		}

		private DateTime UnixTimeStampToDateTime(long unixTimeStamp)
		{
			var dateTimeVal = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

			dateTimeVal = dateTimeVal.AddSeconds(unixTimeStamp).ToLocalTime();

			return dateTimeVal;
		}

		private async Task<AuthResult> GenerateJwtTokens(IdentityUser user)
		{
			var jwtTokenHandler = new JwtSecurityTokenHandler();

			var key = Encoding.ASCII.GetBytes(_jwtConfig.Secret);

			var tokenDescriptor = new SecurityTokenDescriptor
			{
				Subject = new ClaimsIdentity(
					new[]{
							new Claim("Id", user.Id),
							new Claim(JwtRegisteredClaimNames.Email, user.Email),
							new Claim(JwtRegisteredClaimNames.Sub, user.Email),
							new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
						  }),
				Expires = DateTime.UtcNow.AddMinutes(5),  //5-10 minutes
				SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
			};

			var token = jwtTokenHandler.CreateToken(tokenDescriptor);
			var jwtToken = jwtTokenHandler.WriteToken(token);

			var refreshToken = new RefreshToken()
			{
				JwtId = token.Id,
				IsUsed = false,
				IsRevorked = false,
				UserId = user.Id,
				AddedDate = DateTime.UtcNow,
				ExpiryDate = DateTime.UtcNow.AddMonths(6),
				Token = RandomString(35) + Guid.NewGuid()
			};

			await _apiDbContext.RefreshTokens.AddAsync(refreshToken);
			await _apiDbContext.SaveChangesAsync();

			return new AuthResult()
			{
				Token = jwtToken,
				Sucess = true,
				RefreshToken = refreshToken.Token
			};
		}

		private string RandomString(int length)
		{
			var random = new Random();
			var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
			return new string(Enumerable.Repeat(chars, length).Select(x => x[random.Next(x.Length)]).ToArray());
		}
	}
}
