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


        /// <summary>
        /// Refresh token respository used to persist refreshtokens
        /// </summary>
        /// <param name="context"></param>
        public RefreshTokenRepository(FlexinetsContext context)
        {
            _context = context;
        }


        /// <summary>
        /// Save a refresh token
        /// Returns the refresh token id
        /// </summary>
        /// <param name="refreshToken"></param>
        /// <returns>Refresh token id</returns>
        public async Task<String> SaveRefreshTokenAsync(RefreshTokenModel refreshToken)
        {
            var refreshTokenId = Guid.NewGuid().ToString("n");
            _context.RefreshTokens.Add(new RefreshTokens
            {
                ClientId = "notneeded",
                ExpiresUtc = refreshToken.ExpiresUtc,
                IssuedUtc = refreshToken.IssuedUtc,
                ProtectedTicket = refreshToken.AccessToken,
                Subject = refreshToken.Subject,
                TokenIdHash = CryptoMethods.GetSHA512Hash(refreshTokenId)
            });
            await _context.SaveChangesAsync();
            return refreshTokenId;
        }


        /// <summary>
        /// Get a 
        /// </summary>
        /// <param name="refreshTokenId"></param>
        /// <returns></returns>
        public async Task<RefreshTokenModel> GetRefreshTokenAsync(String refreshTokenId)
        {
            var token = await _context.RefreshTokens.SingleOrDefaultAsync(o => o.TokenIdHash == CryptoMethods.GetSHA512Hash(refreshTokenId) && o.ExpiresUtc >= DateTime.UtcNow);
            return token != null ? new RefreshTokenModel
            {
                ExpiresUtc = token.ExpiresUtc,
                IssuedUtc = token.IssuedUtc,
                AccessToken = token.ProtectedTicket,
                Subject = token.Subject
            } : null;
        }


        /// <summary>
        /// Remove a token
        /// </summary>
        /// <param name="tokenId"></param>
        /// <returns></returns>
        public async Task RemoveTokenAsync(String tokenId)
        {
            using (var transaction = await _context.Database.BeginTransactionAsync())
            {
                var token = await _context.RefreshTokens.SingleOrDefaultAsync(o => o.TokenIdHash == CryptoMethods.GetSHA512Hash(tokenId));
                if (token != null)
                {
                    _context.RefreshTokens.Remove(token);
                    await _context.SaveChangesAsync();
                    transaction.Commit();
                }
            }
        }
    }
}