package com.marcusdacoregio.multipleauthenticationmanager;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/cat")
public class CatController {

	@GetMapping
	public String helloCat() {
		return "Hello Cat";
	}

}
