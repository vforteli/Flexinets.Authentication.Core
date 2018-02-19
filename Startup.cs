using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Flexinets.Authentication;
using Flexinets.Core.Database.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Azure.KeyVault;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json.Serialization;

namespace FlexinetsAuthentication.Core
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddCors();
            services.AddTransient<RefreshTokenRepository>();
            services.AddTransient<AdminAuthenticationProvider>();
            services.AddDbContext<FlexinetsContext>(options => options.UseSqlServer(Configuration.GetConnectionString("FlexinetsContext")));

            //var kvClient = new KeyVaultClient(new KeyVaultClient.AuthenticationCallback(GetToken));
            //var certificate = kvClient.GetCertificateAsync("changeme").Result;
            //services.AddSingleton(new SigningCredentialsProvider(new SigningCredentials(new X509SecurityKey(new X509Certificate2(certificate.)), SecurityAlgorithms.RsaSha512)));
            services.AddSingleton(new SigningCredentialsProvider(new SigningCredentials(new X509SecurityKey(new X509Certificate2("C:/users/verne/desktop/jwtkey.pfx", "testkey")), SecurityAlgorithms.RsaSha512)));

            ConfigureAuthentication(services);

            services.AddMvc().AddJsonOptions(options => options.SerializerSettings.ContractResolver = new DefaultContractResolver());
        }

        private void ConfigureAuthentication(IServiceCollection services)
        {
            services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(o =>
            {
                o.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    ValidIssuer = Configuration["Jwt:Issuer"],
                    ValidAudience = Configuration["Jwt:Audience"],
                    IssuerSigningKey = new X509SecurityKey(new X509Certificate2("C:/users/verne/desktop/jwtkey.cer"))   // todo inject or use azure key vault maybe...
                };
            });
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseCors(o => o.AllowAnyOrigin().AllowAnyHeader().AllowAnyMethod().AllowCredentials());
            app.UseAuthentication();
            app.UseMvc();
        }


        public static async Task<String> GetToken(String authority, String resource, String scope)
        {
            var authContext = new AuthenticationContext(authority);
            var clientCred = new ClientCredential("changeme", "changeme");  // todo inject
            var result = await authContext.AcquireTokenAsync(resource, clientCred);
            if (result == null)
            {
                throw new InvalidOperationException("Failed to obtain the JWT token");
            }

            return result.AccessToken;
        }
    }
}
