using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;

namespace SimpleOAuth2.ResourceServer
{
    public class Startup
    {
        public Startup(IHostingEnvironment env)
        {
            var builder = new ConfigurationBuilder()
                .SetBasePath(env.ContentRootPath)
                .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
                .AddJsonFile($"appsettings.{env.EnvironmentName}.json", optional: true)
                .AddEnvironmentVariables();
            Configuration = builder.Build();
        }

        public IConfigurationRoot Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            // Add framework services.
            services.AddMvc();

            // Add authorization policies
            var issuer = Configuration["TokenValidation:Issuer"];
            services.AddAuthorization(options =>
            {
                options.AddPolicy("read:timesheets",
                    policy => policy.Requirements.Add(new HasScopeRequirement("read:timesheets", issuer)));
                options.AddPolicy("create:timesheets",
                    policy => policy.Requirements.Add(new HasScopeRequirement("create:timesheets", issuer)));
            });            
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env, ILoggerFactory loggerFactory)
        {
            loggerFactory.AddConsole(Configuration.GetSection("Logging"));
            loggerFactory.AddDebug();

            // validate OAuth2 bearer token as a symmetrically-signed JWT
            var options = new JwtBearerOptions
            {
                TokenValidationParameters =
                {
                    ValidIssuer = Configuration["TokenValidation:Issuer"],
                    ValidAudience = Configuration["TokenValidation:Audience"],
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Configuration["TokenValidation:SigningKeySecret"]))
                }
            };
            app.UseJwtBearerAuthentication(options);

            app.UseMvc();
        }
    }
}
