package de.gupta.hermes.api;

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.LinkedHashSet;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

final class TokenIssuancePolicyTest
{
	@Test
	void shouldApplyDefaultClaimNames()
	{
		final TokenIssuancePolicy policy = TokenIssuancePolicy.of("hermes", Set.of("internal-api"),
				Duration.ofMinutes(30));

		assertThat(policy.roleClaimName()).isEqualTo("roles");
		assertThat(policy.versionClaimName()).isEqualTo("ver");
		assertThat(policy.upstreamIssuerClaimName()).contains("upstream_iss");
		assertThat(policy.includeTokenId()).isTrue();
	}

	@Test
	void shouldDefensivelyCopyAudiences()
	{
		final Set<String> audiences = new LinkedHashSet<>();
		audiences.add("internal-api");

		final TokenIssuancePolicy policy = TokenIssuancePolicy.of("hermes", audiences, Duration.ofMinutes(30));
		audiences.add("mutated");

		assertThat(policy.audiences()).containsExactly("internal-api");
	}

	@Test
	void shouldRejectNonPositiveTimeToLive()
	{
		assertThatThrownBy(() -> TokenIssuancePolicy.of("hermes", Set.of(), Duration.ZERO))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("timeToLive must be positive");
	}

	@Test
	void shouldRejectBlankUpstreamIssuerClaimNameWhenPresent()
	{
		assertThatThrownBy(() -> TokenIssuancePolicy.of("hermes",
				Set.of(),
				Duration.ofMinutes(15),
				"roles",
				"ver",
				Optional.of(" "),
				false))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("upstreamIssuerClaimName must not be blank");
	}

	@Test
	void shouldRejectNullUpstreamIssuerClaimOptional()
	{
		assertThatThrownBy(() -> TokenIssuancePolicy.of("hermes",
				Set.of(),
				Duration.ofMinutes(15),
				"roles",
				"ver",
				null,
				false))
				.isInstanceOf(NullPointerException.class)
				.hasMessage("upstreamIssuerClaimName must not be null");
	}
}