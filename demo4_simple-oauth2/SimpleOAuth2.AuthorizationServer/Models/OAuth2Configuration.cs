namespace SimpleOAuth2.AuthorizationServer.Models
{
        public class OAuth2Configuration
        {
            public string[] AllowedScopes { get; set; }
            public OAuth2Client[] Clients { get; set; }
        }
}
