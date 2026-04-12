package de.gupta.hermes.application.service;

import de.gupta.hermes.HermesTestTokens;
import de.gupta.security.hermes.api.CustomClaimEnricher;
import de.gupta.security.hermes.api.TokenExchangeConfiguration;
import de.gupta.security.hermes.api.TokenIssuancePolicy;
import de.gupta.security.hermes.application.service.InternalTokenExchangeService;
import de.gupta.security.hermes.application.service.InternalTokenExchangeServiceFactory;
import de.gupta.security.hermes.domain.model.ExchangeFailure;
import de.gupta.security.hermes.domain.model.ExchangeFailureReason;
import de.gupta.security.hermes.domain.model.ExchangeResult;
import de.gupta.security.hermes.domain.model.ExchangeSuccess;
import de.gupta.security.themis.api.TokenVerificationConfiguration;
import de.gupta.security.themis.api.TokenVerificationPolicy;
import de.gupta.security.themis.api.TokenVerifier;
import de.gupta.security.themis.api.TokenVerifierFactory;
import io.jsonwebtoken.security.WeakKeyException;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Consumer;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
final class TokenExchangeServiceExchangeTest
{
	private static final Clock FIXED_CLOCK =
			Clock.fixed(Instant.parse("2026-04-08T10:15:30Z"), ZoneOffset.UTC);

	private InternalTokenExchangeService service(final TokenExchangeConfiguration<TestUser> configuration)
	{
		return service(TokenVerifierFactory.hmac(
						TokenVerificationConfiguration.of(TokenVerificationPolicy.of(Duration.ZERO, true)),
						HermesTestTokens.UPSTREAM_SECRET),
				TokenIssuancePolicy.of("hermes", Set.of("internal-api"), Duration.ofMinutes(30)),
				HermesTestTokens.INTERNAL_SECRET,
				configuration);
	}

	private InternalTokenExchangeService service(final TokenVerifier verifier,
	                                             final TokenIssuancePolicy issuancePolicy,
	                                             final String internalSecret,
	                                             final TokenExchangeConfiguration<TestUser> configuration)
	{
		return InternalTokenExchangeServiceFactory.create(verifier, issuancePolicy, internalSecret, configuration);
	}

	private TokenExchangeConfiguration<TestUser> defaultConfiguration()
	{
		return TokenExchangeConfiguration.of(externalId -> Optional.of(new TestUser("local-1", externalId)),
				TestUser::id,
				_ -> Set.of("ROLE_USER"),
				CustomClaimEnricher.none(),
				FIXED_CLOCK);
	}

	@Nested
	@TestInstance(TestInstance.Lifecycle.PER_CLASS)
	final class SuccessCases
	{
		@ParameterizedTest(name = "{0}")
		@MethodSource("successCases")
		void shouldExchangeUpstreamToken(final SuccessCase testCase)
		{
			final ExchangeResult result = service(testCase.configuration())
					.exchange(testCase.token(), FIXED_CLOCK.instant());

			assertThat(result).isInstanceOf(ExchangeSuccess.class);
			testCase.assertions().accept((ExchangeSuccess) result);
		}

		@Test
		void shouldPreferCanonicalClaimsOverCustomClaimCollisions()
		{
			final TokenExchangeConfiguration<TestUser> configuration = TokenExchangeConfiguration.of(
					externalId -> Optional.of(new TestUser("local-1", externalId)),
					TestUser::id,
					_ -> Set.of("ROLE_USER"),
					(_, _) -> Map.of(
							"sub", "attacker-subject",
							"iss", "attacker-issuer",
							"roles", List.of("ROLE_ATTACKER"),
							"upstream_iss", "attacker-upstream"),
					FIXED_CLOCK);

			final ExchangeResult result = service(configuration)
					.exchange(HermesTestTokens.upstreamTokenWithSubject("external-1"), FIXED_CLOCK.instant());

			assertThat(result).isInstanceOf(ExchangeSuccess.class);
			final Map<String, Object> claims =
					HermesTestTokens.parseInternalClaims(((ExchangeSuccess) result).token().token(), FIXED_CLOCK);
			assertThat(claims.get("sub")).isEqualTo("local-1");
			assertThat(claims.get("iss")).isEqualTo("hermes");
			assertThat(HermesTestTokens.rolesFromClaims(claims)).containsExactly("ROLE_USER");
			assertThat(claims.get("upstream_iss")).isEqualTo("https://supabase.example");
		}

		@Test
		void shouldOmitAudienceJtiAndUpstreamIssuerClaimsFromIssuedJwtWhenDisabled()
		{
			final TokenIssuancePolicy issuancePolicy = TokenIssuancePolicy.of("hermes",
					Set.of(),
					Duration.ofMinutes(30),
					"roles",
					Optional.empty(),
					false);

			final ExchangeResult result = service(TokenVerifierFactory.hmac(
							TokenVerificationConfiguration.of(TokenVerificationPolicy.of(Duration.ZERO, true)),
							HermesTestTokens.UPSTREAM_SECRET),
					issuancePolicy,
					HermesTestTokens.INTERNAL_SECRET,
					defaultConfiguration())
					.exchange(HermesTestTokens.upstreamTokenWithSubject("external-1"), FIXED_CLOCK.instant());

			assertThat(result).isInstanceOf(ExchangeSuccess.class);
			final ExchangeSuccess success = (ExchangeSuccess) result;
			assertThat(success.token().tokenId()).isEmpty();
			assertThat(success.token().upstreamIssuer()).contains("https://supabase.example");
			final Map<String, Object> claims =
					HermesTestTokens.parseInternalClaims(success.token().token(), FIXED_CLOCK);
			assertThat(claims).doesNotContainKeys("aud", "jti", "upstream_iss");
		}

		private Stream<Arguments> successCases()
		{
			return Stream.of(
					SuccessCase.of("resolve by subject",
							HermesTestTokens.upstreamTokenWithSubject("external-1"),
							defaultConfiguration(),
							success -> assertThat(success.token().subject()).isEqualTo("local-1")),
					SuccessCase.of("resolve by configurable email claim",
							HermesTestTokens.upstreamTokenWithEmail("provider-subject", "alice@example.com"),
							TokenExchangeConfiguration.of("email",
									externalId -> Optional.of(new TestUser("local-alice", externalId)),
									TestUser::id,
									_ -> Set.of("ROLE_REPORTING"),
									(_, _) -> Map.of("department", "finance"),
									FIXED_CLOCK),
							success ->
							{
								assertThat(success.token().subject()).isEqualTo("local-alice");
								assertThat(success.token().roles()).containsExactly("ROLE_REPORTING");
								assertThat(HermesTestTokens.parseInternalClaims(success.token().token(), FIXED_CLOCK)
								                           .get("department"))
										.isEqualTo("finance");
							}))
			             .map(Arguments::of);
		}
	}

	@Nested
	@TestInstance(TestInstance.Lifecycle.PER_CLASS)
	final class FailureCases
	{
		@ParameterizedTest(name = "{0}")
		@MethodSource("failureCases")
		void shouldReturnFailure(final FailureCase testCase)
		{
			final ExchangeResult result = service(testCase.configuration())
					.exchange(testCase.token(), FIXED_CLOCK.instant());

			assertThat(result).isInstanceOf(ExchangeFailure.class);
			assertThat(((ExchangeFailure) result).reason()).isEqualTo(testCase.expectedReason());
		}

		@Test
		void shouldRejectInvalidInternalSigningSecretDuringConstruction()
		{
			assertThatThrownBy(() -> service(TokenVerifierFactory.hmac(
							TokenVerificationConfiguration.of(TokenVerificationPolicy.of(Duration.ZERO, true)),
							HermesTestTokens.UPSTREAM_SECRET),
					TokenIssuancePolicy.of("hermes", Set.of("internal-api"), Duration.ofMinutes(30)),
					"short-secret",
					defaultConfiguration()))
					.isInstanceOf(WeakKeyException.class);
		}

		@Test
		void shouldPropagateVerifierExceptions()
		{
			final TokenVerifier explodingVerifier = _ ->
			{
				throw new IllegalStateException("verifier exploded");
			};

			assertThatThrownBy(() -> service(explodingVerifier,
						TokenIssuancePolicy.of("hermes", Set.of("internal-api"), Duration.ofMinutes(30)),
						HermesTestTokens.INTERNAL_SECRET,
						defaultConfiguration())
					.exchange("irrelevant", FIXED_CLOCK.instant()))
					.isInstanceOf(IllegalStateException.class)
					.hasMessage("verifier exploded");
		}

		private Stream<Arguments> failureCases()
		{
			return Stream.of(
					FailureCase.of("upstream verification failure",
							"not-a-jwt",
							defaultConfiguration(),
							ExchangeFailureReason.UPSTREAM_VERIFICATION_FAILED),
					FailureCase.of("missing configured external identity claim",
							HermesTestTokens.upstreamTokenWithoutClaim("provider-subject"),
							TokenExchangeConfiguration.of("email",
									externalId -> Optional.of(new TestUser("local", externalId)),
									TestUser::id,
									_ -> Set.of(),
									CustomClaimEnricher.none(),
									FIXED_CLOCK),
							ExchangeFailureReason.MISSING_EXTERNAL_IDENTITY),
								 FailureCase.of("missing local subject",
										 HermesTestTokens.upstreamTokenWithSubject("provider-subject"),
										 TokenExchangeConfiguration.of(externalId -> Optional.of(new TestUser("", externalId)),
												 TestUser::id,
												 _ -> Set.of(),
												 CustomClaimEnricher.none(),
												 FIXED_CLOCK),
							ExchangeFailureReason.MISSING_LOCAL_SUBJECT))
			             .map(Arguments::of);
		}
	}

	private record SuccessCase(String description, String token, TokenExchangeConfiguration<TestUser> configuration,
	                           Consumer<ExchangeSuccess> assertions)
	{
		@Override
		public String toString()
		{
			return description;
		}

		private static SuccessCase of(final String description,
		                              final String token,
		                              final TokenExchangeConfiguration<TestUser> configuration,
		                              final Consumer<ExchangeSuccess> assertions)
		{
			return new SuccessCase(description, token, configuration, assertions);
		}
	}

	private record FailureCase(String description, String token, TokenExchangeConfiguration<TestUser> configuration,
	                           ExchangeFailureReason expectedReason)
	{
		@Override
		public String toString()
		{
			return description;
		}

		private static FailureCase of(final String description,
		                              final String token,
		                              final TokenExchangeConfiguration<TestUser> configuration,
		                              final ExchangeFailureReason expectedReason)
		{
			return new FailureCase(description, token, configuration, expectedReason);
		}
	}

	private record TestUser(String id, String externalId)
	{
	}
}