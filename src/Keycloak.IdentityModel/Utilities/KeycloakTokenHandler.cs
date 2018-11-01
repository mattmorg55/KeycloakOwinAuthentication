using Keycloak.IdentityModel.Models.Configuration;
using Microsoft.IdentityModel;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http;
using System.Threading.Tasks;

namespace Keycloak.IdentityModel.Utilities
{
	internal class KeycloakTokenHandler : JwtSecurityTokenHandler
	{

		public bool TryValidateToken(string jwt, IKeycloakParameters options, OidcDataManager uriManager, out SecurityToken rToken, bool isRefreshToken = false)
		{
			try
			{
				rToken = ValidateToken(jwt, options, uriManager, isRefreshToken);
				return true;
			}
			catch (Exception)
			{
				rToken = null;
				return false;
			}
		}

		public async Task<SecurityToken> ValidateTokenAsync(string jwt, IKeycloakParameters options, bool isRefreshToken = false)
		{
			var uriManager = await OidcDataManager.GetCachedContextAsync(options);
			return ValidateToken(jwt, options, uriManager, isRefreshToken);
		}

		public SecurityToken ValidateToken(string jwt, IKeycloakParameters options, OidcDataManager uriManager, bool isRefreshToken = false)
		{
			var tokenValidationParameters = new TokenValidationParameters
			{
				ValidateLifetime = true,
				RequireExpirationTime = true,
				ValidateIssuer = !options.DisableIssuerValidation,
				ValidateAudience = !options.DisableAudienceValidation,
				ValidateIssuerSigningKey = !options.DisableIssuerSigningKeyValidation,
				RequireSignedTokens = !options.AllowUnsignedTokens,
				ValidIssuer = uriManager.GetIssuer(),
				ClockSkew = options.TokenClockSkew,
				ValidAudiences = new List<string> { "null", options.ClientId },
				IssuerSigningKeys = uriManager.GetJsonWebKeys().GetSigningKeys(),
				AuthenticationType = options.AuthenticationType // Not used
			};

			bool disableSignatureValidation = isRefreshToken && options.DisableRefreshTokenSignatureValidation;
			return ValidateToken(jwt, tokenValidationParameters, disableSignatureValidation);
		}

		protected bool TryValidateToken(string securityToken, TokenValidationParameters validationParameters,
				out SecurityToken rToken)
		{
			try
			{
				rToken = ValidateToken(securityToken, validationParameters, false);
				return true;
			}
			catch (Exception)
			{
				rToken = null;
				return false;
			}
		}

		protected SecurityToken ValidateToken(string securityToken, TokenValidationParameters validationParameters, bool disableSignatureValidation)
		{
			////////////////////////////////
			// Copied from MS Source Code //
			////////////////////////////////

			if (string.IsNullOrWhiteSpace(securityToken))
			{
				throw new ArgumentNullException(nameof(securityToken));
			}

			if (validationParameters == null)
			{
				throw new ArgumentNullException(nameof(validationParameters));
			}

			if (securityToken.Length > MaximumTokenSizeInBytes)
			{
				throw new ArgumentException(string.Format(CultureInfo.InvariantCulture, Constants.ErrorMessages.IDX10209,
						securityToken.Length, MaximumTokenSizeInBytes));
			}

		    	JwtSecurityToken jwt;
			if (!disableSignatureValidation)
				{
					// For access & id tokens, parse the token and validate signature.
					jwt = ValidateSignature(securityToken, validationParameters);

					if (jwt.SigningKey != null)
					{
					ValidateIssuerSecurityKey(jwt.SigningKey, jwt, validationParameters);
					}
			}
				else
			{
				// Disabling signature for refresh tokens.
				// This is an option that can be used to fix compatibility with Keycloak v4.5 that switched to use HS256 encryption for Refresh tokens (before it as RS256, the same as for Access tokens)
				// Refresh tokens should not be necessary to validate, as they should only be used by sending it back to Keycloak server when necessary. Keycloak server itself validates refresh tokens. The applications should not use the information in the Refresh token.
				// Ref: https://issues.jboss.org/browse/KEYCLOAK-4622
				jwt = ReadJwtToken(securityToken);
			}

			DateTime? notBefore = null;
			if (jwt.Payload.Nbf != null)
			{
				notBefore = jwt.ValidFrom;
			}

			DateTime? expires = null;
			if (jwt.Payload.Exp != null)
			{
				expires = jwt.ValidTo;
			}

			Validators.ValidateTokenReplay(securityToken, expires, validationParameters);
			if (validationParameters.ValidateLifetime)
			{
				if (validationParameters.LifetimeValidator != null)
				{
					if (!validationParameters.LifetimeValidator(notBefore, expires, jwt, validationParameters))
					{
						throw new SecurityTokenInvalidLifetimeException(string.Format(CultureInfo.InvariantCulture,
								Constants.ErrorMessages.IDX10230, jwt));
					}
				}
				else
				{
					ValidateLifetime(notBefore, expires, jwt, validationParameters);
				}
			}

			if (validationParameters.ValidateAudience)
			{
				if (validationParameters.AudienceValidator != null)
				{
					if (!validationParameters.AudienceValidator(jwt.Audiences, jwt, validationParameters))
					{
						throw new SecurityTokenInvalidAudienceException(string.Format(CultureInfo.InvariantCulture,
								Constants.ErrorMessages.IDX10231, jwt));
					}
				}
				else
				{
					ValidateAudience(jwt.Audiences, jwt, validationParameters);
				}
			}

			var issuer = jwt.Issuer;
			if (validationParameters.ValidateIssuer)
			{
				issuer = validationParameters.IssuerValidator != null
						? validationParameters.IssuerValidator(issuer, jwt, validationParameters)
						: ValidateIssuer(issuer, jwt, validationParameters);
			}

			if (validationParameters.ValidateActor && !string.IsNullOrWhiteSpace(jwt.Actor))
			{
				SecurityToken actor;
				ValidateToken(jwt.Actor, validationParameters, out actor);
			}

			return jwt;
		}
	}
}