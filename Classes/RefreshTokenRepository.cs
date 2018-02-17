using Flexinets.Core.Database.Models;
using Flexinets.Security;
using Microsoft.EntityFrameworkCore;
using System;
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


        public async Task<String> SaveTokenAsync(RefreshTokenModel token)
        {
            var refreshTokenId = Guid.NewGuid().ToString("n");
            _context.RefreshTokens.Add(new RefreshTokens
            {
                ClientId = token.ClientId,
                ExpiresUtc = token.ExpiresUtc,
                IssuedUtc = token.IssuedUtc,
                ProtectedTicket = token.ProtectedTicket,
                Subject = token.Subject,
                TokenIdHash = CryptoMethods.GetSHA512Hash(refreshTokenId)
            });
            await _context.SaveChangesAsync();
            return refreshTokenId;
        }


        public async Task<RefreshTokenModel> GetTokenAsync(String tokenId)
        {
            var token = await _context.RefreshTokens.SingleOrDefaultAsync(o => o.TokenIdHash == CryptoMethods.GetSHA512Hash(tokenId));
            return token != null ? new RefreshTokenModel
            {
                ClientId = token.ClientId,
                ExpiresUtc = token.ExpiresUtc,
                IssuedUtc = token.IssuedUtc,
                ProtectedTicket = token.ProtectedTicket,
                Subject = token.Subject
            } : null;
        }


        public async Task RemoveTokenAsync(String tokenId)
        {
            var token = await _context.RefreshTokens.SingleOrDefaultAsync(o => o.TokenIdHash == CryptoMethods.GetSHA512Hash(tokenId));
            if (token != null)
            {
                _context.RefreshTokens.Remove(token);
                await _context.SaveChangesAsync();
            }
        }
    }
}