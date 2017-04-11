namespace SimpleOAuth2.AuthorizationServer.Models
{
  public class OAuth2Grant
    {
        public int ID { get; set; }
        public string ClientId { get; set; }
        public string UserId { get; set; }
        public string Scope { get; set; }
    }
}
