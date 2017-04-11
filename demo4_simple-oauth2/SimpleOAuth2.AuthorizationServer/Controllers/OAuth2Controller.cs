using System;
using System.Collections.Generic;
using System.Linq;
using System.IdentityModel.Tokens.Jwt;
using System.Threading.Tasks;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;
using SimpleOAuth2.AuthorizationServer.Data;
using SimpleOAuth2.AuthorizationServer.Models;
using SimpleOAuth2.AuthorizationServer.Models.OAuth2ViewModels;

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

        private async Task<OAuth2Grant> GetExistingGrant(string clientId, string userId)
        {
            var existingGrant = await _dbContext.Grants
                .SingleOrDefaultAsync(g => g.ClientId == clientId && g.UserId == userId);
            
            return existingGrant;
        }

        private async Task UpstertGrantRecord(OAuth2Grant existingGrant, string grantedScopes, string clientId, string userId)
        {
            var grant = existingGrant == null ? new OAuth2Grant() : existingGrant;
            grant.Scope = grantedScopes;
            if (existingGrant == null)
            {
                grant.ClientId = clientId;
                grant.UserId = userId;

                _dbContext.Add(grant);
            }
            await _dbContext.SaveChangesAsync();
        }

        private async Task<ActionResult> CreateAuthorizationCodeAndRedirect (string clientId, string userId, string redirectUri, string state)
        {
            // create authorization code
            var authorizationCode = new OAuth2AuthorizationCode
            {
                Code = Guid.NewGuid().ToString("N"),
                ClientId = clientId,
                UserId = userId,
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

        private RedirectResult OAuth2AuthorizationError(string redirectUrl, string state, string error, string errorDescription)
        {
            var query = new Dictionary<string, string>
            {
                { "error", error },
                { "error_description", errorDescription }
            };
            if (!string.IsNullOrEmpty(state))
            {
                query["state"] = state;
            }
            var finalUrl = QueryHelpers.AddQueryString(redirectUrl, query);

            return Redirect(finalUrl);
        }

        private JsonResult OAuth2TokenError(string error, string errorDescription)
        {
            Response.StatusCode = 400;
            return Json(new
            {
                error,
                error_description = errorDescription
            });
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

            // get requested scopes
            var scope = Request.Query["scope"];
            var requestedScopes = string.IsNullOrEmpty(scope) ? new string[] {} : ((string) scope).Split(' ');

            // calculate possible granted scopes
            var grantedScopes = string.Join(" ",
                _oauth2Configuration.AllowedScopes
                    .Where(s => requestedScopes.Any(ss => ss == s)));

            // fetch current user ID
            var userId = (await _userManager.GetUserAsync(User)).Id;

            // fetch existing grant (if any)
            var existingGrant = await GetExistingGrant(clientId, userId);

            // check to see if the existing grant has the same scopes
            if (existingGrant != null && existingGrant.Scope == grantedScopes) 
            {
                // no change in grant
                return await CreateAuthorizationCodeAndRedirect(clientId, userId, redirectUri, state);
            }
            else if (client.IsFirstParty)
            {
                // update grant without consent since its a first party app
                await UpstertGrantRecord(existingGrant, grantedScopes, clientId, userId);

                return await CreateAuthorizationCodeAndRedirect(clientId, userId, redirectUri, state);
            }
            else 
            {
                // third party app: redirect to consent page so user can grant access
                TempData["ClientName"] = client.ClientName;
                TempData["ClientId"] = clientId.ToString();
                TempData["GrantedScopes"] = grantedScopes;
                TempData["RedirectUri"] = redirectUri.ToString();
                TempData["State"] = state.ToString();

                return RedirectToAction("Consent");
            }
        }

        [HttpGet]
        [Authorize]
        public async Task<ActionResult> Consent()
        {
            // rehydrate and validate TempData passed from the authorize request
            var viewModel = new ConsentViewModel
            {
                ClientName = (string) TempData["ClientName"],
                ClientId = (string) TempData["ClientId"],
                GrantedScopes = (string) TempData["GrantedScopes"],
                RedirectUri = (string) TempData["RedirectUri"],
                // state can be empty
                State = (string) TempData["State"]
            };
            if (string.IsNullOrEmpty(viewModel.ClientName) || 
                string.IsNullOrEmpty(viewModel.ClientId) || 
                string.IsNullOrEmpty(viewModel.GrantedScopes) || 
                string.IsNullOrEmpty(viewModel.RedirectUri))
            {
                return StatusCode(400, "Invalid request");
            }

            // fetch current user ID
            var userId = (await _userManager.GetUserAsync(User)).Id;

            return View(viewModel);
        }

        [HttpPost]
        [Authorize]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> ConsentAllow(ConsentViewModel viewModel)
        {
            // fetch current user ID
            var userId = (await _userManager.GetUserAsync(User)).Id;

            // fetch existing grant (if any)
            var existingGrant = await GetExistingGrant(viewModel.ClientId, userId);

            // update grant record
            await UpstertGrantRecord(existingGrant, viewModel.GrantedScopes, viewModel.ClientId, userId);

            return await CreateAuthorizationCodeAndRedirect(viewModel.ClientId, userId, viewModel.RedirectUri, viewModel.State);
        }

        [HttpPost]
        [Authorize]
        [ValidateAntiForgeryToken]
        public ActionResult ConsentDeny(ConsentViewModel viewModel)
        {
            return OAuth2AuthorizationError(
                viewModel.RedirectUri, 
                viewModel.State,
                "access_denied", 
                "The resource owner denied the request for authorization.");
        }
        
        [HttpPost]
        public async Task<ActionResult> Token(TokenModel model)
        {
            // authenticate client credentials
            if (!_oauth2Clients.ContainsKey(model.client_id)) {
                return OAuth2TokenError("invalid_client", "Invalid client ID or secret.");
            }
            var client = _oauth2Clients[model.client_id];
            if (model.client_secret != client.ClientSecret) {
                return OAuth2TokenError("invalid_client", "Invalid client ID or secret.");
            }

            // validate grant_type
            if (string.IsNullOrEmpty(model.grant_type))
            {
                return OAuth2TokenError("invalid_request", "Missing required parameter: grant_type");
            }
            if (model.grant_type != "authorization_code")
            {
                return OAuth2TokenError("unsupported_grant_type", "Unsupported grant type");
            }

            // validate code
            if (string.IsNullOrEmpty(model.code))
            {
                return OAuth2TokenError("invalid_request", "Missing required parameter: code");
            }

            // validate redirect_uri
            if (string.IsNullOrEmpty(model.redirect_uri))
            {
                return OAuth2TokenError("invalid_request", "Missing required parameter: redirect_uri");
            }

            // fetch and remove authorization code record (one time use)
            var authorizationCode = await _dbContext.AuthorizationCodes
                .SingleOrDefaultAsync(c => c.Code == model.code);
            if (authorizationCode == null)
            {
                return OAuth2TokenError("invalid_request", "Invalid authorization code");
            }
            _dbContext.Remove(authorizationCode);
            await _dbContext.SaveChangesAsync();

            // validate authorization code record
            if (model.redirect_uri != authorizationCode.RedirectUri)
            {
                return OAuth2TokenError("invalid_request", "Invalid redirect URI");
            }
            if (model.client_id != authorizationCode.ClientId)
            {
                return OAuth2TokenError("invalid_request", "Client ID does not match authorization code record");
            }

            // fetch grant record
            var grant = await _dbContext.Grants
                .SingleOrDefaultAsync(g => g.ClientId == authorizationCode.ClientId &&
                                           g.UserId == authorizationCode.UserId);
            if (grant == null)
            {
                return OAuth2TokenError("invalid_request", "Grant record associated with this authorization code no longer exists");
            }
            
            // generate access token
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(
                    new Claim[] { 
                        new Claim("sub", authorizationCode.UserId),
                        new Claim("scope", grant.Scope)
                    }),
                Issuer = "https://oauth.example.com/",
                Audience = "https://api.example.com/",
                IssuedAt = DateTime.UtcNow,
                Expires = DateTime.UtcNow.AddSeconds(3600),
                SigningCredentials = new SigningCredentials(
                    new SymmetricSecurityKey(Encoding.UTF8.GetBytes("this-is-my-super-secure-secret")), 
                    SecurityAlgorithms.HmacSha256)
            };
            var tokenHandler = new JwtSecurityTokenHandler();
            var accessToken = tokenHandler.CreateEncodedJwt(tokenDescriptor);

            return Json(new 
            {
                access_token = accessToken,
                token_type = "Bearer",
                expires_in = 3600
            });
        }
    }
}
