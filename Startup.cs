using Flexinets.Authentication;
using Flexinets.Common.WebCore;
using Flexinets.Core.Communication.Mail;
using Flexinets.Core.Database.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json.Serialization;
using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;

namespace FlexinetsAuthentication.Core
{
    public class Startup
    {
        public Startup(IConfiguration configuration, IHostingEnvironment environment)
        {
            Configuration = configuration;
            Environment = environment;
        }

        public IConfiguration Configuration { get; }
        public IHostingEnvironment Environment { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddCors();
            services.AddTransient<RefreshTokenRepository>();
            services.AddTransient<AdminAuthenticationProvider>();
            services.AddDbContext<FlexinetsContext>(options => options.UseSqlServer(Configuration.GetConnectionString("FlexinetsContext")));
            services.AddSingleton(new SigningCredentialsProvider(GetSigningCredentials()));
            services.AddScoped<ISmtpClient>(o => new SmtpClient(
               Configuration["SmtpClient:host"],
               Convert.ToUInt16(Configuration["SmtpClient:port"]),
               Configuration["SmtpClient:username"],
               Configuration["SmtpClient:password"]));
            ConfigureAuthentication(services);

            services.AddMvcCore(o => o.Filters.Add(typeof(LogExceptionFilterAttribute))).AddCors().AddJsonFormatters(options => options.ContractResolver = new DefaultContractResolver());
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
                    IssuerSigningKey = GetIssuerSigningKey()
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


        /// <summary>
        /// Get the signing credentials from somewhere
        /// </summary>
        /// <returns></returns>
        private SigningCredentials GetSigningCredentials()
        {
            return new SigningCredentials(new X509SecurityKey(new X509Certificate2(Path.Combine(Environment.ContentRootPath, Configuration["Jwt:SigningCertificatePfx"]), Configuration["Jwt:SigningCertificatePassword"])), SecurityAlgorithms.RsaSha512);
        }


        /// <summary>
        /// Get the issuer signing key from somewhere
        /// </summary>
        /// <param name="env"></param>
        /// <returns></returns>
        private X509SecurityKey GetIssuerSigningKey()
        {
            return new X509SecurityKey(new X509Certificate2(Path.Combine(Environment.ContentRootPath, Configuration["Jwt:SigningCertificateCer"])));
        }
    }
}
