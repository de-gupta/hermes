package de.gupta.hermes.domain.model;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

final class IssuedTokenTest
{
	@Test
	void shouldDefensivelyCopyAudiencesAndRoles()
	{
		final Set<String> audiences = new LinkedHashSet<>(Set.of("internal-api"));
		final Set<String> roles = new LinkedHashSet<>(Set.of("ROLE_USER"));

		final IssuedToken issuedToken = IssuedToken.of("token-value",
				"local-1",
				"hermes",
				audiences,
				Instant.parse("2026-04-08T10:15:30Z"),
				Instant.parse("2026-04-08T10:45:30Z"),
				roles,
				3L,
				Optional.of("jti-1"),
				Optional.of("https://issuer.example"));

		audiences.add("mutated");
		roles.add("ROLE_ADMIN");

		assertThat(issuedToken.audiences()).containsExactly("internal-api");
		assertThat(issuedToken.roles()).containsExactly("ROLE_USER");
	}

	@Test
	void shouldSupportValueSemantics()
	{
		final IssuedToken left = IssuedToken.of("token-value",
				"local-1",
				"hermes",
				Set.of("internal-api"),
				Instant.parse("2026-04-08T10:15:30Z"),
				Instant.parse("2026-04-08T10:45:30Z"),
				Set.of("ROLE_USER"),
				3L,
				Optional.of("jti-1"),
				Optional.of("https://issuer.example"));
		final IssuedToken right = IssuedToken.of("token-value",
				"local-1",
				"hermes",
				Set.of("internal-api"),
				Instant.parse("2026-04-08T10:15:30Z"),
				Instant.parse("2026-04-08T10:45:30Z"),
				Set.of("ROLE_USER"),
				3L,
				Optional.of("jti-1"),
				Optional.of("https://issuer.example"));

		assertThat(left).isEqualTo(right).hasSameHashCodeAs(right);
		assertThat(left).hasToString(right.toString());
	}

	@Test
	void shouldRejectBlankSubject()
	{
		assertThatThrownBy(() -> IssuedToken.of("token-value",
				" ",
				"hermes",
				Set.of(),
				Instant.parse("2026-04-08T10:15:30Z"),
				Instant.parse("2026-04-08T10:45:30Z"),
				Set.of(),
				3L,
				Optional.empty(),
				Optional.empty()))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("subject must not be blank");
	}

	@Test
	void shouldRejectNullOptionals()
	{
		assertThatThrownBy(() -> IssuedToken.of("token-value",
				"local-1",
				"hermes",
				Set.of(),
				Instant.parse("2026-04-08T10:15:30Z"),
				Instant.parse("2026-04-08T10:45:30Z"),
				Set.of(),
				3L,
				null,
				Optional.empty()))
				.isInstanceOf(NullPointerException.class)
				.hasMessage("tokenId must not be null");
	}
}
