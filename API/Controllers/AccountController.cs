using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using API.Data;
using API.DTOs;
using API.Entities;
using API.Interfaces;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers
{
    public class AccountController : BaseApiController
    {
        private readonly DataContext _context;
        private readonly ITokenService _tokenService;

        public AccountController(DataContext context, ITokenService tokenService)
        {
            _tokenService = tokenService;
            _context = context;
        }


        [HttpPost("register")]

        public async Task<ActionResult<UserDto>> Register(RegisterDto regdto)
        {
            if (await UserExists(regdto.UserName)) return BadRequest("User Exizts");
            using var hmac = new HMACSHA512();
            var user = new AppUser
            {
                UserName = regdto.UserName.ToLower(),
                PasswordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(regdto.Password)),
                PasswordSalt = hmac.Key
            };
            _context.User.Add(user);
            await _context.SaveChangesAsync();
            return new UserDto
            {
                Username=user.UserName,
                Token=_tokenService.CreateToken(user)
            };
        }

        [HttpPost("login")]

        public async Task<ActionResult<UserDto>> Login(LoginDto logDto)
        {

            var user = await _context.User.SingleOrDefaultAsync(x => x.UserName == logDto.UserName);
            if (user == null) return Unauthorized("InvalidUser");
            using var hmac = new HMACSHA512(user.PasswordSalt);
            var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(logDto.Password));
            for (int i = 0; i < computedHash.Length; i++)
            {
                if (computedHash[i] != user.PasswordHash[i]) return Unauthorized("Invalid Password");
            }
           return new UserDto
            {
                Username=user.UserName,
                Token=_tokenService.CreateToken(user)
            };

        }

        private async Task<bool> UserExists(string username)
        {
            return await _context.User.AnyAsync(x => x.UserName == username.ToLower());
        }
    }
}