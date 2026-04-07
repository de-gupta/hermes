package de.gupta.security.hermes.api;

@FunctionalInterface
public interface LocalSubjectResolver<User>
{
	String resolveSubject(final User user);
}