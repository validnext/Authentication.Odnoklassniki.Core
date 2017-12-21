using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using System.Linq;

namespace Authentication.Odnoklassniki.Core
{
    internal class OdnoklassnikiHandler : OAuthHandler<OdnoklassnikiOptions>
    {
        public OdnoklassnikiHandler(IOptionsMonitor<OdnoklassnikiOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock)
            : base(options, logger, encoder, clock)
        { }

        protected override async Task<AuthenticationTicket> CreateTicketAsync(
            ClaimsIdentity identity,
            Microsoft.AspNetCore.Authentication.AuthenticationProperties properties,
            OAuthTokenResponse tokens)
        {
            var address = QueryHelpers.AddQueryString(Options.UserInformationEndpoint, "access_token", tokens.AccessToken);

            Dictionary<string, string> queryString = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["application_key"] = Options.PublicKey,
                ["format"] = "json",
                ["__online"] = "false"
            };

            if (Options.Fields.Count != 0)
            {
                queryString.Add("fields", string.Join(",", Options.Fields));
            }

            queryString.Add("sig", GetSignature(tokens.AccessToken, queryString));

            address = QueryHelpers.AddQueryString(address, queryString);

            var response = await Backchannel.GetAsync(address, Context.RequestAborted);
            if (!response.IsSuccessStatusCode)
            {
                Logger.LogError("Произошла ошибка при получении профиля пользователя: удаленный сервер " +
                                "вернул {Status} ответ со следующей информацией: {Headers} {Body}.",
                                response.StatusCode,
                                response.Headers.ToString(),
                                await response.Content.ReadAsStringAsync());

                throw new HttpRequestException("Произошла ошибка при получении профиля пользователя.");
            }

            var payload = JObject.Parse(await response.Content.ReadAsStringAsync());
            var user = (JObject)payload;
            
            //identity.AddOptionalClaim(ClaimTypes.NameIdentifier, user.Value<string>("uid"), Options.ClaimsIssuer)
            //        .AddOptionalClaim(ClaimTypes.Name, user.Value<string>("name"), Options.ClaimsIssuer)
            //        .AddOptionalClaim(ClaimTypes.GivenName, user.Value<string>("first_name"), Options.ClaimsIssuer)
            //        .AddOptionalClaim(ClaimTypes.Surname, user.Value<string>("last_name"), Options.ClaimsIssuer)
            //        .AddOptionalClaim(ClaimTypes.Email, user.Value<string>("email"), Options.ClaimsIssuer);


            var context = new OAuthCreatingTicketContext(new ClaimsPrincipal(identity), properties, Context, Scheme, Options, Backchannel, tokens, user);

            context.RunClaimActions();

            await Options.Events.CreatingTicket(context);

            return new AuthenticationTicket(context.Principal, context.Properties, Scheme.Name);
        }


        protected string GetSignature(string accessToken, Dictionary<string, string> parameters)
        {
            var parametersValue = string.Concat(parameters.OrderBy(p => p.Key).Select(p => $"{p.Key}={p.Value}"));

            var utf8nobom = new UTF8Encoding(false);

            string GetMd5Hash(string input)
            {
                using (var provider = MD5.Create())
                {
                    var bytes = utf8nobom.GetBytes(input);
                    bytes = provider.ComputeHash(bytes);
                    return BitConverter.ToString(bytes).Replace("-", "").ToLowerInvariant();
                }
            }

            return GetMd5Hash(parametersValue + GetMd5Hash(accessToken + Options.ClientSecret));
        }
    }
}
