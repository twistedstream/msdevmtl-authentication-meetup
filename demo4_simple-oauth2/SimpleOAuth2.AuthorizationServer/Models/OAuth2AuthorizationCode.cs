namespace SimpleOAuth2.AuthorizationServer.Models
{
  public class OAuth2AuthorizationCode
    {
        public int ID { get; set; }
        public string Code { get; set; }
        public string ClientId { get; set; }
        public string UserId { get; set; }
        public string RedirectUri { get; set; }
    }
}
