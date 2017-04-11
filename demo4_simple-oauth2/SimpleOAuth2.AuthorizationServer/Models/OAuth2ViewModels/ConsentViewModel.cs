namespace SimpleOAuth2.AuthorizationServer.Models.OAuth2ViewModels
{
    public class ConsentViewModel
    {
        public string ClientId { get; set; }
        public string ClientName { get; set; }
        public string GrantedScopes { get; set; }
        public string RedirectUri { get; set; }
        public string State { get; set; }
    }
}
