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

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
		import org.springframework.security.oauth2.jwt.Jwt;
		import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

/**
 * @author Josh Cummings
 */
@RestController
public class OAuth2ResourceServerController {

	@GetMapping("/")
	@ResponseBody
	public String index(@AuthenticationPrincipal Jwt jwt) {
		return "this is the root";
	}

	@PreAuthorize("hasAnyScope('SCOPE1')")
	@GetMapping("/needscope1")
	@ResponseBody
	public String needscope1() {
		return "scope1 can see this";
	}

	@PreAuthorize("hasAnyScope('SCOPE2')")
	@GetMapping("/needscope2")
	@ResponseBody
	public String needscope2() {
		return "scope2 can see this";
	}

	@PreAuthorize("hasAnyScope('SCOPE1', 'SCOPE2')")
	@GetMapping("/needscope1orscope2")
	@ResponseBody
	public String needscope1orscope2() {
		return "scope1 or scope 2 can see this";
	}

	@PreAuthorize("isAuthenticated()")
	@GetMapping("/needauthenticated")
	@ResponseBody
	public String needauthenticated() {
		return "any authenticated can see this";
	}
}