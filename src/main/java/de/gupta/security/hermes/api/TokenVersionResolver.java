package de.gupta.security.hermes.api;

@FunctionalInterface
public interface TokenVersionResolver<User>
{
	long resolveVersion(final User user);
}