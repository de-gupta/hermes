package de.gupta.hermes.api;

@FunctionalInterface
public interface LocalSubjectResolver<User>
{
	String resolveSubject(final User user);
}