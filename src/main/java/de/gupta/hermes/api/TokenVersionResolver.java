package de.gupta.hermes.api;

@FunctionalInterface
public interface TokenVersionResolver<User>
{
	long resolveVersion(final User user);
}