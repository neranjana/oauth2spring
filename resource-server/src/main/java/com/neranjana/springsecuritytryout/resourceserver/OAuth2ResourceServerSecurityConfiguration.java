/*
 * Copyright 2002-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.neranjana.springsecuritytryout.resourceserver;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

/**
 * @author Josh Cummings
 */
@EnableWebSecurity
@Configuration
//@EnableGlobalMethodSecurity(prePostEnabled = true)
public class OAuth2ResourceServerSecurityConfiguration extends WebSecurityConfigurerAdapter {

	@Override
	protected void configure(HttpSecurity http) throws Exception {

		// @formatter:off
		http
				.authorizeRequests()
				.antMatchers("/needscope1/**").hasAuthority("SCOPE_SCOPE1")
				.antMatchers("/needscope2/**").hasAuthority("SCOPE_SCOPE2")
				.antMatchers("/needscope1orscope2").hasAnyAuthority("SCOPE_SCOPE1", "SCOPE_SCOPE2")
				.antMatchers("/needauthenticated/**").authenticated()
				.anyRequest().authenticated()
				.and()
				.oauth2ResourceServer()
				.jwt();
		// @formatter:on
	}
}