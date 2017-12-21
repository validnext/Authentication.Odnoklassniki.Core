using System;
using System.Collections.Generic;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using System.Globalization;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Http;

namespace Authentication.Odnoklassniki.Core
{
    public class OdnoklassnikiOptions : OAuthOptions
    {
        public OdnoklassnikiOptions()
        {
            ClaimsIssuer = OdnoklassnikiDefaults.ClaimsIssuer;
            CallbackPath = new PathString(OdnoklassnikiDefaults.CallbackPath);
            AuthorizationEndpoint = OdnoklassnikiDefaults.AuthorizationEndpoint;
            TokenEndpoint = OdnoklassnikiDefaults.TokenEndpoint;
            UserInformationEndpoint = OdnoklassnikiDefaults.UserInformationEndpoint;

            Scope.Add("VALUABLE_ACCESS");
            Scope.Add("GET_EMAIL");

            ClaimActions.MapJsonKey(ClaimTypes.NameIdentifier, "uid");
            ClaimActions.MapJsonKey(ClaimTypes.Name, "name");
            ClaimActions.MapJsonKey(ClaimTypes.Email, "email", ClaimValueTypes.Email);
            ClaimActions.MapJsonKey(ClaimTypes.GivenName, "first_name");
            ClaimActions.MapJsonKey(ClaimTypes.Surname, "last_name");
            ClaimActions.MapJsonKey("urn:odnoklassniki:link", "pic_1");
        }

        public override void Validate()
        {
            if (string.IsNullOrEmpty(ClientId))
            {
                throw new ArgumentException(string.Format(CultureInfo.CurrentCulture, "Отсутствует {0}", nameof(ClientId)), nameof(ClientId));
            }

            if (string.IsNullOrEmpty(ClientSecret))
            {
                throw new ArgumentException(string.Format(CultureInfo.CurrentCulture, "Отсутствует {0}", nameof(ClientSecret)), nameof(ClientSecret));
            }

            if (string.IsNullOrEmpty(PublicKey))
            {
                throw new ArgumentException(string.Format(CultureInfo.CurrentCulture, "Отсутствует {0}", nameof(PublicKey)), nameof(PublicKey));
            }

            base.Validate();
        }

        public string PublicKey { get; set; }

        public ISet<string> Fields { get; } = new HashSet<string>
        {
            "uid",
            "name",
            "email",
            "first_name",
            "last_name",
            "pic_1"
        };
    }
}
