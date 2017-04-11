using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authorization;
using SimpleOAuth2.AuthorizationServer.Data;
using SimpleOAuth2.AuthorizationServer.Models;

namespace SimpleOAuth2.AuthorizationServer.Controllers
{
    public class OAuth2Controller : Controller
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ApplicationDbContext _dbContext;
        private readonly OAuth2Configuration _oauth2Configuration;
        private readonly IDictionary<string, OAuth2Client> _oauth2Clients;

        public OAuth2Controller(UserManager<ApplicationUser> userManager, ApplicationDbContext dbContext, IOptions<OAuth2Configuration> oauth2Configuration)
        {
            _userManager = userManager;
            _dbContext = dbContext;
            _oauth2Configuration = oauth2Configuration.Value;
            _oauth2Clients = _oauth2Configuration.Clients.ToDictionary(c => c.ClientId);
        }

        [HttpGet]
        [Authorize]
        public async Task<ActionResult> Authorize()
        {
            // validate client_id
            var clientId = Request.Query["client_id"];
            if (string.IsNullOrEmpty(clientId))
            {
                return StatusCode(400, "Missing required parameter: client_id");
            }
            if (!_oauth2Clients.ContainsKey(clientId)) {
                return StatusCode(400, $"Unknown client: {clientId}");
            }
            var client = _oauth2Clients[clientId];

            // validate response_type
            var responseType = Request.Query["response_type"];
            if (string.IsNullOrEmpty(responseType))
            {
                return StatusCode(400, "Missing required parameter: response_type");
            }
            if (responseType != "code")
            {
                return StatusCode(400, $"Unsupported response type: {responseType}");
            }

            // validate redirect_uri
            var redirectUri = Request.Query["redirect_uri"];
            if (string.IsNullOrEmpty(redirectUri))
            {
                redirectUri = client.AllowedCallbackUrls[0];
            }            
            else 
            {
                // make sure redirect_uri is valid and allowed
                Uri uri;
                if (!Uri.TryCreate(redirectUri, UriKind.Absolute, out uri)) 
                {
                    return StatusCode(400, $"The redirect_uri is not a valid URI: {redirectUri}");
                }
                if (!client.AllowedCallbackUrls.Any(allowedUrl => 
                    Uri.Compare(new Uri(allowedUrl), uri, UriComponents.SchemeAndServer | UriComponents.Path, UriFormat.SafeUnescaped, StringComparison.OrdinalIgnoreCase) == 0))
                {
                    return StatusCode(400, $"The redirect_uri is now allowed: {redirectUri}");
                }
            }

            // state
            var state = Request.Query["state"];

            // scope
            var scope = Request.Query["scope"];
            var requestedScopes = string.IsNullOrEmpty(scope) ? new string[] {} : ((string) scope).Split(' ');

            // create or update the associate grant record
            var grantedScopes = requestedScopes
                .Where(s => _oauth2Configuration.AllowedScopes.Any(ss => ss == s));

            var user = await _userManager.GetUserAsync(User);

            var existingGrant = await _dbContext.Grants
                .SingleOrDefaultAsync(g => g.ClientId == clientId.ToString() && g.UserId == user.Id);

            var grant = existingGrant == null ? new OAuth2Grant() : existingGrant;
            grant.Scope = string.Join(" ", grantedScopes);
            if (existingGrant == null)
            {
                grant.ClientId = clientId;
                grant.UserId = user.Id;

                _dbContext.Add(grant);
            }
            await _dbContext.SaveChangesAsync();

            // create authorization code
            var authorizationCode = new OAuth2AuthorizationCode
            {
                Code = Guid.NewGuid().ToString("N"),
                ClientId = clientId,
                UserId = user.Id,
                RedirectUri = redirectUri
            };
            _dbContext.Add(authorizationCode);
            await _dbContext.SaveChangesAsync();

            // generate final redirect URL
            var queryParams = new Dictionary<string, string>
            {
                { "code", authorizationCode.Code }
            };
            if (!string.IsNullOrEmpty(state))
            {
                queryParams.Add("state", state);
            }

            var finalRedirectUrl = QueryHelpers.AddQueryString(redirectUri, queryParams);
            return Redirect(finalRedirectUrl);
        }
    }
}
