package se.digg.wallet.rhsm.remotehsmbff.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class ResponseProvider {

  public ResponseEntity<String> getResponse(final HttpStatus httpStatus, MediaType mediaType, final String body) {
    final HttpHeaders headers = new HttpHeaders();
    headers.setContentType(mediaType);
    return new ResponseEntity<>(body, headers, httpStatus);
  }

  public ResponseEntity<String> getResponse(final HttpStatus httpStatus, final String body) {
    return new ResponseEntity<>(body, httpStatus);
  }

}
