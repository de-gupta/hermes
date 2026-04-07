package de.gupta.hermes.api;

import de.gupta.aletheia.functional.Unfolding;
import de.gupta.commons.utility.string.StringSanitizationUtility;

import java.time.Clock;
import java.util.Objects;

public final class TokenExchangeConfiguration<User>
{
	private final String externalIdentityClaimName;
	private final UserResolver<String, User> userResolver;
	private final LocalSubjectResolver<User> localSubjectResolver;
	private final RoleResolver<User> roleResolver;
	private final TokenVersionResolver<User> tokenVersionResolver;
	private final CustomClaimEnricher<User> customClaimEnricher;
	private final Clock clock;

	public static <User> TokenExchangeConfiguration<User> of(final UserResolver<String, User> userResolver,
	                                                         final LocalSubjectResolver<User> localSubjectResolver,
	                                                         final RoleResolver<User> roleResolver,
	                                                         final TokenVersionResolver<User> tokenVersionResolver)
	{
		return of("sub",
				userResolver,
				localSubjectResolver,
				roleResolver,
				tokenVersionResolver,
				CustomClaimEnricher.none(),
				Clock.systemUTC());
	}

	public static <User> TokenExchangeConfiguration<User> of(final UserResolver<String, User> userResolver,
	                                                         final LocalSubjectResolver<User> localSubjectResolver,
	                                                         final RoleResolver<User> roleResolver,
	                                                         final TokenVersionResolver<User> tokenVersionResolver,
	                                                         final CustomClaimEnricher<User> customClaimEnricher,
	                                                         final Clock clock)
	{
		return of("sub",
				userResolver,
				localSubjectResolver,
				roleResolver,
				tokenVersionResolver,
				customClaimEnricher,
				clock);
	}

	public static <User> TokenExchangeConfiguration<User> of(final String externalIdentityClaimName,
	                                                         final UserResolver<String, User> userResolver,
	                                                         final LocalSubjectResolver<User> localSubjectResolver,
	                                                         final RoleResolver<User> roleResolver,
	                                                         final TokenVersionResolver<User> tokenVersionResolver,
	                                                         final CustomClaimEnricher<User> customClaimEnricher,
	                                                         final Clock clock)
	{
		final String normalizedClaimName = Unfolding.beckon(externalIdentityClaimName)
		                                            .discern(StringSanitizationUtility::isNotBlank,
															() -> new IllegalArgumentException(
						                                            "externalIdentityClaimName must not be " +
																			"blank"))
		                                            .summon();

		return new TokenExchangeConfiguration<>(normalizedClaimName,
				Objects.requireNonNull(userResolver, "userResolver must not be null"),
				Objects.requireNonNull(localSubjectResolver, "localSubjectResolver must not be null"),
				Objects.requireNonNull(roleResolver, "roleResolver must not be null"),
				Objects.requireNonNull(tokenVersionResolver, "tokenVersionResolver must not be null"),
				Objects.requireNonNull(customClaimEnricher, "customClaimEnricher must not be null"),
				Objects.requireNonNull(clock, "clock must not be null"));
	}

	public String externalIdentityClaimName()
	{
		return externalIdentityClaimName;
	}

	public UserResolver<String, User> userResolver()
	{
		return userResolver;
	}

	public LocalSubjectResolver<User> localSubjectResolver()
	{
		return localSubjectResolver;
	}

	public RoleResolver<User> roleResolver()
	{
		return roleResolver;
	}

	public TokenVersionResolver<User> tokenVersionResolver()
	{
		return tokenVersionResolver;
	}

	public CustomClaimEnricher<User> customClaimEnricher()
	{
		return customClaimEnricher;
	}

	public Clock clock()
	{
		return clock;
	}

	private TokenExchangeConfiguration(final String externalIdentityClaimName,
	                                   final UserResolver<String, User> userResolver,
	                                   final LocalSubjectResolver<User> localSubjectResolver,
	                                   final RoleResolver<User> roleResolver,
	                                   final TokenVersionResolver<User> tokenVersionResolver,
	                                   final CustomClaimEnricher<User> customClaimEnricher,
	                                   final Clock clock)
	{
		this.externalIdentityClaimName = externalIdentityClaimName;
		this.userResolver = userResolver;
		this.localSubjectResolver = localSubjectResolver;
		this.roleResolver = roleResolver;
		this.tokenVersionResolver = tokenVersionResolver;
		this.customClaimEnricher = customClaimEnricher;
		this.clock = clock;
	}
}
