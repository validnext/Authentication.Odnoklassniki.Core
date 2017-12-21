using Authentication.Odnoklassniki.Core;
using Microsoft.AspNetCore.Authentication;
using System;

namespace Microsoft.Extensions.DependencyInjection
{
    public static class OdnoklassnikiAuthenticationOptionsExtensions
    {
        public static AuthenticationBuilder AddOdnoklassniki(this AuthenticationBuilder builder)
            => builder.AddOdnoklassniki(OdnoklassnikiDefaults.AuthenticationScheme, _ => { });

        public static AuthenticationBuilder AddOdnoklassniki(this AuthenticationBuilder builder, Action<OdnoklassnikiOptions> configureOptions)
            => builder.AddOdnoklassniki(OdnoklassnikiDefaults.AuthenticationScheme, configureOptions);

        public static AuthenticationBuilder AddOdnoklassniki(this AuthenticationBuilder builder, string authenticationScheme, Action<OdnoklassnikiOptions> configureOptions)
            => builder.AddOdnoklassniki(authenticationScheme, OdnoklassnikiDefaults.DisplayName, configureOptions);

        public static AuthenticationBuilder AddOdnoklassniki(this AuthenticationBuilder builder, string authenticationScheme, string displayName, Action<OdnoklassnikiOptions> configureOptions)
            => builder.AddOAuth<OdnoklassnikiOptions, OdnoklassnikiHandler>(authenticationScheme, displayName, configureOptions);
    }
}
