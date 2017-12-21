namespace Authentication.Odnoklassniki.Core
{
    public static class OdnoklassnikiDefaults
    {
        public const string ClaimsIssuer = "Odnoklassniki";
        public const string AuthenticationScheme = "Odnoklassniki";
        public static readonly string DisplayName = "Odnoklassniki";
        public static readonly string AuthorizationEndpoint = "https://connect.ok.ru/oauth/authorize";
        public static readonly string TokenEndpoint = "https://api.ok.ru/oauth/token.do";
        public static readonly string UserInformationEndpoint = "https://api.ok.ru/api/users/getCurrentUser";
        public static readonly string CallbackPath = "/signin-odnoklassniki";
    }
}
