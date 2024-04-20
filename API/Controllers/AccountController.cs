using System.Security.Claims;
using API.DTOs;
using API.Services;
using Domain;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Infrastructure;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers
{
    [AllowAnonymous]
    [ApiController]
    [Route("api/[controller]")]
    public class AccountController : ControllerBase
    {
        private UserManager<AppUser> _userManger;
        private readonly TokenService _tokenService;
        private readonly IConfiguration _config;
        private readonly HttpClient _httpClient;

        public AccountController(UserManager<AppUser> userManger, TokenService tokenService, IConfiguration config)
        {
            this._config = config;
            this._tokenService = tokenService;
            _userManger = userManger;
            _httpClient = new HttpClient{
                BaseAddress = new Uri("https://graph.facebook.com/")
            };

        }

        
        [HttpPost("login")]
        public async Task<ActionResult<UserDto>> Login(LoginDto loginDto)
        {
            var user = await _userManger.Users.Include(x=> x.Photos).FirstOrDefaultAsync(x => x.Email == loginDto.Email);
            if (user == null) return Unauthorized();
            var result = await _userManger.CheckPasswordAsync(user, loginDto.Password);

            if (result)
            {
                return CreateUserObject(user);
            }
            return Unauthorized();
        }

        [HttpPost("register")]
        public async Task<ActionResult<UserDto>> Register(RegisterDto registerDto)
        {
            if (await _userManger.Users.AnyAsync(x => x.UserName == registerDto.UserName))
            {
                ModelState.AddModelError("username", "Username is alreadt taken");
                return ValidationProblem();
            }
            if (await _userManger.Users.AnyAsync(x => x.Email == registerDto.Email))
            {
                ModelState.AddModelError("email","Email is already taken");
                return ValidationProblem();
            }

            var user = new AppUser
            {
                DisplayName = registerDto.DisplayName,
                Email = registerDto.Email,
                UserName = registerDto.UserName
            };

            var result = await _userManger.CreateAsync(user, registerDto.Password);

            if (result.Succeeded)
            {
                return CreateUserObject(user);
            }

            return BadRequest(result.Errors);
        }


        [Authorize]
        [HttpGet]
        public async Task<ActionResult<UserDto>> GetCurrentUser()
        {
            var user = await _userManger.Users.Include(x=>x.Photos).FirstOrDefaultAsync(x=>x.Email == User.FindFirstValue(ClaimTypes.Email));

            return CreateUserObject(user);
        }

        [AllowAnonymous]
        [HttpPost("fbLogin")]
        public async Task<ActionResult<UserDto>> FacebookLogin(string accessToken)
        {

            var fbVerifyKeys = _config["Facebook:AppId"] + "|" + _config["Facebook:ApiSecret"];

            // var verifyTokenResponse = await _httpClient.GetAsync($"debug_token?input_token={accessToken}&accesstoken={fbVerifyKeys}");

            // if (!verifyTokenResponse.IsSuccessStatusCode) return Unauthorized();

            var fbUrl = $"me?access_token={accessToken}&fields=name,email,picture.width(100).height(100)";

            var fbInfo =  await _httpClient.GetFromJsonAsync<FacebookDto>(fbUrl);

            var user = await _userManger.Users.Include(p=>p.Photos).FirstOrDefaultAsync(x=>x.Email == fbInfo.Email);

            if(user!=null) return CreateUserObject(user);

            user = new AppUser{
                DisplayName = fbInfo.Name,
                Email = fbInfo.Email,
                UserName = fbInfo.Email,
                Photos = new List<Photo>{
                    new Photo{
                        Id = "fb_" + fbInfo.Id,
                        Url = fbInfo.Picture.Data.Url,
                        IsMain= true
                    }
                }

            };

            var result =  await _userManger.CreateAsync(user);
            if(!result.Succeeded) return BadRequest("Problem creating user account from facebook");

            return CreateUserObject(user);

        }

        private UserDto CreateUserObject(AppUser user)
        {
            return new UserDto
            {
                DisplayName = user.DisplayName,
                Image = user?.Photos?.FirstOrDefault(x=> x.IsMain)?.Url,
                Token = _tokenService.CreateToken(user),
                Username = user.UserName
            };
        }

        [HttpDelete]
        public async Task<ActionResult> Delete(){
            var user = await _userManger.Users.Include(p=>p.Photos).FirstOrDefaultAsync(x=>x.Email == "eblack_man@yahoo.com");
            if(user==null) return NotFound();

            await _userManger.DeleteAsync(user);
            
            return Ok();            
        }

    }
}