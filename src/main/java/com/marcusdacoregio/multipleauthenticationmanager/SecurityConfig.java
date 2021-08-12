package com.marcusdacoregio.multipleauthenticationmanager;

import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.springframework.context.annotation.Bean;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationConverter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

@EnableWebSecurity
public class SecurityConfig {

	@Bean
	@Order(1)
	public SecurityFilterChain dogApiSecurity(HttpSecurity http) throws Exception {
		http.requestMatchers((matchers) -> matchers
				.antMatchers("/dog/**"));
		http.authorizeRequests((authz) -> authz
				.anyRequest().authenticated());
		http.httpBasic();
		http.authenticationProvider(new DogAuthenticationProvider());
		return http.build();
	}

	@Bean
	@Order(1)
	public SecurityFilterChain catApiSecurity(HttpSecurity http) throws Exception {
		http.requestMatchers((matchers) -> matchers
				.antMatchers("/cat/**"));
		http.authorizeRequests((authz) -> authz
				.anyRequest().authenticated());
		http.httpBasic();
		http.authenticationProvider(new CatAuthenticationProvider());
		return http.build();
	}

	@Bean
	@Order(2)
	public SecurityFilterChain apiSecurity(HttpSecurity http) throws Exception {
		http.authorizeRequests((authz) -> authz
				.anyRequest().authenticated());
		http.addFilterBefore(apiAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
		return http.build();
	}

	private AuthenticationFilter apiAuthenticationFilter() {
		AuthenticationFilter authenticationFilter = new AuthenticationFilter(new ApiAuthenticationManagerResolver(), new BasicAuthenticationConverter());
		authenticationFilter.setSuccessHandler((request, response, authentication) -> {});
		return authenticationFilter;
	}

	public static class ApiAuthenticationManagerResolver implements AuthenticationManagerResolver<HttpServletRequest> {

		private final Map<RequestMatcher, AuthenticationManager> managers = Map.of(
				new AntPathRequestMatcher("/dog/**"), new DogAuthenticationProvider()::authenticate,
				new AntPathRequestMatcher("/cat/**"), new CatAuthenticationProvider()::authenticate
		);

		@Override
		public AuthenticationManager resolve(HttpServletRequest request) {
			for (Map.Entry<RequestMatcher, AuthenticationManager> entry : managers.entrySet()) {
				if (entry.getKey().matches(request)) {
					return entry.getValue();
				}
			}
			throw new IllegalArgumentException("Unable to resolve AuthenticationManager");
		}
	}

	public static class DogAuthenticationProvider implements AuthenticationProvider {

		@Override
		public Authentication authenticate(Authentication authentication) throws AuthenticationException {
			if (authentication.getName().endsWith("_dog")) {
				return new UsernamePasswordAuthenticationToken(authentication.getName(), authentication.getCredentials(),
						AuthorityUtils.createAuthorityList("ROLE_DOG"));
			}
			throw new BadCredentialsException("Username should end with _dog");
		}

		@Override
		public boolean supports(Class<?> authentication) {
			return true;
		}

	}

	public static class CatAuthenticationProvider implements AuthenticationProvider {

		@Override
		public Authentication authenticate(Authentication authentication) throws AuthenticationException {
			if (authentication.getName().endsWith("_cat")) {
				return new UsernamePasswordAuthenticationToken(authentication.getName(), authentication.getCredentials(),
						AuthorityUtils.createAuthorityList("ROLE_CAT"));
			}
			throw new BadCredentialsException("Username should end with _cat");
		}

		@Override
		public boolean supports(Class<?> authentication) {
			return true;
		}

	}

}
