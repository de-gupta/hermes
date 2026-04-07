package de.gupta.hermes.application.service;

import de.gupta.commons.security.api.TokenVerificationPolicy;
import de.gupta.commons.security.api.TokenVerifierFactory;
import de.gupta.hermes.HermesTestTokens;
import de.gupta.hermes.api.CustomClaimEnricher;
import de.gupta.hermes.api.TokenExchangeConfiguration;
import de.gupta.hermes.api.TokenIssuancePolicy;
import de.gupta.hermes.domain.model.ExchangeFailure;
import de.gupta.hermes.domain.model.ExchangeFailureReason;
import de.gupta.hermes.domain.model.ExchangeResult;
import de.gupta.hermes.domain.model.ExchangeSuccess;
import org.junit.jupiter.api.Nested;
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
import java.util.function.Consumer;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
final class TokenExchangeServiceExchangeTest
{
	private static final Clock FIXED_CLOCK =
			Clock.fixed(Instant.parse("2026-04-08T10:15:30Z"), ZoneOffset.UTC);

	private TokenExchangeService service(final TokenExchangeConfiguration<TestUser> configuration)
	{
		return TokenExchangeServiceFactory.create(
				TokenVerifierFactory.hmac(TokenVerificationPolicy.of(Duration.ZERO, true), HermesTestTokens.UPSTREAM_SECRET),
				TokenIssuancePolicy.of("hermes", Set.of("internal-api"), Duration.ofMinutes(30)),
				HermesTestTokens.INTERNAL_SECRET,
				configuration);
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
					.exchange(TokenExchangeRequest.of(testCase.token(), FIXED_CLOCK.instant()));

			assertThat(result).isInstanceOf(ExchangeSuccess.class);
			testCase.assertions().accept((ExchangeSuccess) result);
		}

		private Stream<Arguments> successCases()
		{
			return Stream.of(
					SuccessCase.of("resolve by subject",
							HermesTestTokens.upstreamTokenWithSubject("external-1"),
							TokenExchangeConfiguration.of(externalId -> Optional.of(new TestUser("local-1", externalId)),
									TestUser::id,
									user -> Set.of("ROLE_USER"),
									user -> 3L,
									CustomClaimEnricher.none(),
									FIXED_CLOCK),
							success ->
							{
								assertThat(success.token().subject()).isEqualTo("local-1");
								assertThat(success.token().version()).isEqualTo(3L);
							}),
					SuccessCase.of("resolve by configurable email claim",
							HermesTestTokens.upstreamTokenWithEmail("provider-subject", "alice@example.com"),
							TokenExchangeConfiguration.of("email",
									externalId -> Optional.of(new TestUser("local-alice", externalId)),
									TestUser::id,
									user -> Set.of("ROLE_REPORTING"),
									user -> 11L,
									(user, upstreamToken) -> Map.of("department", "finance"),
									FIXED_CLOCK),
							success ->
							{
								assertThat(success.token().subject()).isEqualTo("local-alice");
								assertThat(success.token().roles()).containsExactly("ROLE_REPORTING");
								assertThat(HermesTestTokens.parseInternalClaims(success.token().token()).get("department"))
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
					.exchange(TokenExchangeRequest.of(testCase.token(), FIXED_CLOCK.instant()));

			assertThat(result).isInstanceOf(ExchangeFailure.class);
			assertThat(((ExchangeFailure) result).reason()).isEqualTo(testCase.expectedReason());
		}

		private Stream<Arguments> failureCases()
		{
			return Stream.of(
					FailureCase.of("upstream verification failure",
							"not-a-jwt",
							TokenExchangeConfiguration.of(externalId -> Optional.of(new TestUser("local", externalId)),
									TestUser::id,
									user -> Set.of(),
									user -> 1L,
									CustomClaimEnricher.none(),
									FIXED_CLOCK),
							ExchangeFailureReason.UPSTREAM_VERIFICATION_FAILED),
					FailureCase.of("missing configured external identity claim",
							HermesTestTokens.upstreamTokenWithoutClaim("provider-subject"),
							TokenExchangeConfiguration.of("email",
									externalId -> Optional.of(new TestUser("local", externalId)),
									TestUser::id,
									user -> Set.of(),
									user -> 1L,
									CustomClaimEnricher.none(),
									FIXED_CLOCK),
							ExchangeFailureReason.MISSING_EXTERNAL_IDENTITY),
					FailureCase.of("missing local subject",
							HermesTestTokens.upstreamTokenWithSubject("provider-subject"),
							TokenExchangeConfiguration.of(externalId -> Optional.of(new TestUser("", externalId)),
									TestUser::id,
									user -> Set.of(),
									user -> 1L,
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