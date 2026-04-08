module de.gupta.security.hermes
{
	exports de.gupta.security.hermes.api;
	exports de.gupta.security.hermes.domain.model;

	requires jjwt.api;

	requires de.gupta.themis;
	requires de.gupta.aletheia;
	requires de.gupta.athena;
}