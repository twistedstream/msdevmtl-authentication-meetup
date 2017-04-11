namespace SimpleOAuth2.AuthorizationServer.Models
{
        public class OAuth2Client
        {
            public string ClientName { get; set; }
            public string ClientId { get; set; }
            public string ClientSecret { get; set; }
            public string[] AllowedCallbackUrls { get; set; }
            public bool IsFirstParty { get; set; }
        }
}

