package com.marcusdacoregio.multipleauthenticationmanager;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/dog")
public class DogController {

	@GetMapping(produces = MediaType.TEXT_PLAIN_VALUE)
	public String helloDog() {
		return "Hello Dog";
	}

}
