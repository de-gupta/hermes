package de.gupta.security.hermes.api;

import java.util.Optional;

@FunctionalInterface
public interface UserResolver<ExternalIdentity, User>
{
	Optional<User> resolveUser(final ExternalIdentity externalIdentity);
}