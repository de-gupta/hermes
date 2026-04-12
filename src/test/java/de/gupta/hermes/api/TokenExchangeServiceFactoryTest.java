package de.gupta.hermes.api;

import de.gupta.hermes.HermesTestTokens;
import de.gupta.security.hermes.api.*;
import de.gupta.security.hermes.domain.model.ExchangeFailure;
import de.gupta.security.hermes.domain.model.ExchangeFailureReason;
import de.gupta.security.hermes.domain.model.ExchangeResult;
import de.gupta.security.hermes.domain.model.ExchangeSuccess;
import de.gupta.security.themis.api.TokenVerificationConfiguration;
import de.gupta.security.themis.api.TokenVerificationPolicy;
import de.gupta.security.themis.api.TokenVerifierFactory;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
final class TokenExchangeServiceFactoryTest
{
	private static final Clock FIXED_CLOCK =
			Clock.fixed(Instant.parse("2026-04-08T10:15:30Z"), ZoneOffset.UTC);

	@ParameterizedTest(name = "{0}")
	@MethodSource("successfulVariants")
	void shouldExchangeVerifiedUpstreamTokenIntoInternalToken(final SigningVariant variant)
	{
		final TokenExchangeService service = variant.serviceFactory().apply(successConfiguration());

		final ExchangeResult result = service.exchange(variant.upstreamToken());

		assertThat(result).isInstanceOf(ExchangeSuccess.class);
		final ExchangeSuccess success = (ExchangeSuccess) result;
		assertThat(success.token().subject()).isEqualTo("local-42");
		assertThat(success.token().roles()).containsExactlyInAnyOrder("ROLE_ADMIN", "ROLE_USER");
		assertThat(success.token().upstreamIssuer()).contains("https://supabase.example");
		assertThat(success.token().tokenId()).isPresent();

		final Map<String, Object> claims = variant.claimsParser().apply(success.token().token(), FIXED_CLOCK);
		assertThat(claims.get("sub")).isEqualTo("local-42");
		assertThat(claims.get("iss")).isEqualTo("Hermes");
		assertThat(HermesTestTokens.rolesFromClaims(claims)).containsExactly("ROLE_ADMIN", "ROLE_USER");
		assertThat(claims.get("tenant")).isEqualTo("acme");
		assertThat(claims.get("upstream_iss")).isEqualTo("https://supabase.example");
	}

	@ParameterizedTest(name = "{0}")
	@MethodSource("successfulVariants")
	void shouldReturnFailureWhenNoLocalUserCanBeResolved(final SigningVariant variant)
	{
		final TokenExchangeService service = variant.serviceFactory().apply(userMissingConfiguration());

		final ExchangeResult result = service.exchange(variant.upstreamToken());

		assertThat(result).isInstanceOf(ExchangeFailure.class);
		assertThat(((ExchangeFailure) result).reason()).isEqualTo(ExchangeFailureReason.USER_NOT_FOUND);
	}

	@ParameterizedTest(name = "{0}")
	@MethodSource("successfulVariants")
	void shouldRejectBlankExternalTokenAtControllerBoundary(final SigningVariant variant)
	{
		final TokenExchangeService service = variant.serviceFactory().apply(blankTokenConfiguration());

		final ExchangeResult result = service.exchange(" ");

		assertThat(result).isInstanceOf(ExchangeFailure.class);
		assertThat(((ExchangeFailure) result).reason()).isEqualTo(ExchangeFailureReason.UPSTREAM_VERIFICATION_FAILED);
		assertThat(((ExchangeFailure) result).details()).contains("externalToken must not be blank");
	}

	private Stream<Arguments> successfulVariants()
	{
		return Stream.of(
							 SigningVariant.of("hmac via policy",
									 configuration -> TokenExchangeServiceFactory.hmac(
											 TokenVerificationConfiguration.of(TokenVerificationPolicy.of(Duration.ZERO, true)),
											 HermesTestTokens.UPSTREAM_SECRET,
											 issuancePolicy(),
											 HermesTestTokens.INTERNAL_SECRET,
											 configuration),
									 HermesTestTokens.upstreamHmacTokenWithSubject("external-123"),
									 HermesTestTokens::parseInternalHmacClaims),
							 SigningVariant.of("hmac via verifier",
									 configuration -> TokenExchangeServiceFactory.hmac(
											 TokenVerifierFactory.hmac(
													 TokenVerificationConfiguration.of(
												             TokenVerificationPolicy.of(Duration.ZERO, true)),
													 HermesTestTokens.UPSTREAM_SECRET),
											 issuancePolicy(),
											 HermesTestTokens.INTERNAL_SECRET,
											 configuration),
									 HermesTestTokens.upstreamHmacTokenWithSubject("external-123"),
									 HermesTestTokens::parseInternalHmacClaims),
							 SigningVariant.of("rsa via policy",
									 configuration -> TokenExchangeServiceFactory.rsa(
											 TokenVerificationConfiguration.of(TokenVerificationPolicy.of(Duration.ZERO, true)),
											 HermesTestTokens.UPSTREAM_RSA_PUBLIC_KEY,
											 issuancePolicy(),
											 HermesTestTokens.INTERNAL_RSA_PRIVATE_KEY,
											 configuration),
									 HermesTestTokens.upstreamRsaTokenWithSubject("external-123"),
									 HermesTestTokens::parseInternalRsaClaims),
							 SigningVariant.of("rsa via verifier",
									 configuration -> TokenExchangeServiceFactory.rsa(
											 TokenVerifierFactory.rsa(
													 TokenVerificationConfiguration.of(
												             TokenVerificationPolicy.of(Duration.ZERO, true)),
													 HermesTestTokens.UPSTREAM_RSA_PUBLIC_KEY),
											 issuancePolicy(),
											 HermesTestTokens.INTERNAL_RSA_PRIVATE_KEY,
											 configuration),
									 HermesTestTokens.upstreamRsaTokenWithSubject("external-123"),
									 HermesTestTokens::parseInternalRsaClaims),
							 SigningVariant.of("ec via policy",
									 configuration -> TokenExchangeServiceFactory.ec(
											 TokenVerificationConfiguration.of(TokenVerificationPolicy.of(Duration.ZERO, true)),
											 HermesTestTokens.UPSTREAM_EC_PUBLIC_KEY,
											 issuancePolicy(),
											 HermesTestTokens.INTERNAL_EC_PRIVATE_KEY,
											 configuration),
									 HermesTestTokens.upstreamEcTokenWithSubject("external-123"),
									 HermesTestTokens::parseInternalEcClaims),
							 SigningVariant.of("ec via verifier",
									 configuration -> TokenExchangeServiceFactory.ec(
											 TokenVerifierFactory.ec(
													 TokenVerificationConfiguration.of(
												             TokenVerificationPolicy.of(Duration.ZERO, true)),
													 HermesTestTokens.UPSTREAM_EC_PUBLIC_KEY),
											 issuancePolicy(),
											 HermesTestTokens.INTERNAL_EC_PRIVATE_KEY,
											 configuration),
									 HermesTestTokens.upstreamEcTokenWithSubject("external-123"),
									 HermesTestTokens::parseInternalEcClaims))
		             .map(Arguments::of);
	}

	private TokenIssuancePolicy issuancePolicy()
	{
		return TokenIssuancePolicy.of("Hermes", Set.of("internal-service"), Duration.ofMinutes(30));
	}

	private TokenExchangeConfiguration<TestUser> successConfiguration()
	{
		return TokenExchangeConfiguration.of(externalId -> Optional.of(new TestUser("local-42", externalId)),
				TestUser::id,
				_ -> Set.of("ROLE_ADMIN", "ROLE_USER"),
				(_, _) -> Map.of("tenant", "acme"),
				FIXED_CLOCK);
	}

	private TokenExchangeConfiguration<TestUser> userMissingConfiguration()
	{
		return TokenExchangeConfiguration.of(_ -> Optional.empty(),
				TestUser::id,
				_ -> Set.of(),
				CustomClaimEnricher.none(),
				FIXED_CLOCK);
	}

	private TokenExchangeConfiguration<TestUser> blankTokenConfiguration()
	{
		return TokenExchangeConfiguration.of(externalId -> Optional.of(new TestUser("local-42", externalId)),
				TestUser::id,
				_ -> Set.of(),
				CustomClaimEnricher.none(),
				FIXED_CLOCK);
	}

	@FunctionalInterface
	private interface BiClaimsParser
	{
		Map<String, Object> apply(String token, Clock clock);
	}

	private record SigningVariant(String description,
	                              Function<TokenExchangeConfiguration<TestUser>, TokenExchangeService> serviceFactory,
	                              String upstreamToken,
	                              BiClaimsParser claimsParser)
	{
		@Override
		public String toString()
		{
			return description;
		}

		private static SigningVariant of(final String description,
		                                 final Function<TokenExchangeConfiguration<TestUser>, TokenExchangeService> serviceFactory,
		                                 final String upstreamToken,
		                                 final BiClaimsParser claimsParser)
		{
			return new SigningVariant(description, serviceFactory, upstreamToken, claimsParser);
		}
	}

	private record TestUser(String id, String externalId)
	{
	}
}