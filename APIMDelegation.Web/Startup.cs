//===============================================================================
// Microsoft FastTrack for Azure
// Azure API Management Sign In Sign Up Delegation Example
//===============================================================================
// Copyright © Microsoft Corporation.  All rights reserved.
// THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY
// OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT
// LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
// FITNESS FOR A PARTICULAR PURPOSE.
//===============================================================================
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.AzureADB2C.UI;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System.Threading.Tasks;

namespace APIMDelegation.Web
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
            // Add the AzureADB2C authentication middleware and populate its values from the 
            // AzureADB2C section of the configuration file
            services.AddAuthentication(AzureADB2CDefaults.AuthenticationScheme)
                .AddAzureADB2C(options => Configuration.GetSection("AzureADB2C").Bind(options));

            // Configure the OpenIDConnect authentication middleware which is leveraged by the
            // AzureADB2C authentication middleware
            services.Configure<OpenIdConnectOptions>(AzureADB2CDefaults.OpenIdScheme, options =>
            {
                // Set the response type to retrieve both an authorization code and an ID token
                options.ResponseType = $"code id_token";

                // Add event handlers to the OpenIdConnect events that we want to respond to during
                // the authentication handshake
                options.Events = new OpenIdConnectEvents
                {
                    // Add the offline_access scope and the scope values for the WebAPI we want to invoke
                    // from configuration to the Scope property of the protocol message before we redirect
                    // to the identity provider. This will ensure our authorization code has the appropriate
                    // scope to retrieve access tokens for the WebAPI.
                    OnRedirectToIdentityProvider = async ctxt =>
                    {
                        ctxt.ProtocolMessage.Scope += $" offline_access {Configuration.GetValue<string>("AzureADB2C:ApiScopes")}";
                        await Task.Yield();
                    }
                };
            });

            services.AddControllersWithViews();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }
            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }
}
