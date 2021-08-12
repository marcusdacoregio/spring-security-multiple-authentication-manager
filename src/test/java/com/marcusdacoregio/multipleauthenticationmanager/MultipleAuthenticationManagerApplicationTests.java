package com.marcusdacoregio.multipleauthenticationmanager;

import org.junit.jupiter.api.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class MultipleAuthenticationManagerApplicationTests {

	@Autowired
	private MockMvc mockMvc;

	@Test
	void whenRequestDogPathWithDogAuthenticationThenReturns() throws Exception {
		this.mockMvc.perform(get("/dog").with(httpBasic("iam_dog", "password")))
				.andExpect(status().isOk());
	}

	@Test
	void whenRequestDogPathWithCatAuthenticationThenUnauthorized() throws Exception {
		this.mockMvc.perform(get("/dog").with(httpBasic("iam_cat", "password")))
				.andExpect(status().isUnauthorized());
	}

	@Test
	void whenRequestDogPathWithWrongAuthenticationThenUnauthorized() throws Exception {
		this.mockMvc.perform(get("/dog").with(httpBasic("not_ending_with_dog_haha", "password")))
				.andExpect(status().isUnauthorized());
	}

	@Test
	void whenRequestCatPathWithCatAuthenticationThenReturns() throws Exception {
		this.mockMvc.perform(get("/cat").with(httpBasic("iam_cat", "password")))
				.andExpect(status().isOk());
	}

	@Test
	void whenRequestCatPathWithDogAuthenticationThenReturns() throws Exception {
		this.mockMvc.perform(get("/cat").with(httpBasic("iam_dog", "password")))
				.andExpect(status().isUnauthorized());
	}

	@Test
	void whenRequestCatPathWithWrongAuthenticationThenUnauthorized() throws Exception {
		this.mockMvc.perform(get("/dog").with(httpBasic("not_ending_with_cat_haha", "password")))
				.andExpect(status().isUnauthorized());
	}

}
