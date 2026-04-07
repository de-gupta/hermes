package de.gupta.hermes.api;

import java.util.Set;

@FunctionalInterface
public interface RoleResolver<User>
{
	Set<String> fetchRoles(final User user);
}