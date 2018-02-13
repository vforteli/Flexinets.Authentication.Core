using Flexinets.Core.Database.Models;
using Microsoft.EntityFrameworkCore;
using System;
using System.Linq;
using System.Threading.Tasks;

namespace Flexinets.Authentication
{
    public class RefreshTokenRepository
    {
        private readonly FlexinetsContext _context;


        public RefreshTokenRepository(FlexinetsContext context)
        {
            _context = context;
        }


        public async Task SaveTokenAsync(RefreshTokenModel token)
        {
            _context.RefreshTokens.Add(new RefreshTokens
            {
                ClientId = token.ClientId,
                ExpiresUtc = token.ExpiresUtc,
                IssuedUtc = token.IssuedUtc,
                ProtectedTicket = token.ProtectedTicket,
                Subject = token.Subject,
                TokenIdHash = token.Id
            });
            await _context.SaveChangesAsync();
        }


        public async Task<RefreshTokenModel> GetTokenAsync(String tokenIdHash)
        {
            return await _context.RefreshTokens.Select(o => new RefreshTokenModel
            {
                ClientId = o.ClientId,
                ExpiresUtc = o.ExpiresUtc,
                IssuedUtc = o.IssuedUtc,
                ProtectedTicket = o.ProtectedTicket,
                Subject = o.Subject,
                Id = o.TokenIdHash
            }).SingleOrDefaultAsync(o => o.Id == tokenIdHash);
        }


        public async Task RemoveTokenAsync(String tokenIdHash)
        {
            var token = await _context.RefreshTokens.SingleOrDefaultAsync(o => o.TokenIdHash == tokenIdHash);
            if (token != null)
            {
                _context.RefreshTokens.Remove(token);
                await _context.SaveChangesAsync();
            }
        }
    }
}