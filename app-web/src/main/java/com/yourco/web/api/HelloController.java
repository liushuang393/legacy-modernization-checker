package com.yourco.web.api;

import jakarta.validation.constraints.NotBlank;
import org.springframework.http.MediaType;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * サンプル API
 * - 入力検証（Bean Validation）の例
 */
@RestController
@Validated
public class HelloController {

  @GetMapping(value = "/api/hello", produces = MediaType.APPLICATION_JSON_VALUE)
  public Message hello(@RequestParam @NotBlank String name) {
    return new Message("hello, " + name);
  }

  public record Message(String message) {}
}
