package se.digg.wallet.rhsm.hsmserver.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSObject;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import se.digg.wallet.r2ps.commons.StaticResources;
import se.digg.wallet.r2ps.commons.dto.ErrorCode;
import se.digg.wallet.r2ps.commons.dto.ErrorResponse;
import se.digg.wallet.r2ps.commons.exception.ServiceRequestHandlingException;
import se.digg.wallet.r2ps.server.service.ServiceRequestHandler;

import java.text.ParseException;

@Slf4j
@RestController
public class ServiceController {

  private static final ObjectMapper objectMapper = StaticResources.SERVICE_EXCHANGE_OBJECT_MAPPER;

  private final ResponseProvider responseProvider;
  private final ServiceRequestHandler serviceRequestHandler;

  @Autowired
  public ServiceController(final ResponseProvider responseProvider, final ServiceRequestHandler serviceRequestHandler) {
    this.responseProvider = responseProvider;
    this.serviceRequestHandler = serviceRequestHandler;
  }

  @PostMapping(value = "/service", produces = MediaType.APPLICATION_JSON_VALUE, consumes = MediaType.APPLICATION_JSON_VALUE)
  public ResponseEntity<String> service(@RequestBody final String serviceRequest) {

    try {
      if (log.isDebugEnabled()) {
        logServiceRequest(serviceRequest);
      }
      final String serviceResponse = serviceRequestHandler.handleServiceRequest(serviceRequest);
      if (log.isDebugEnabled()) {
        logServiceResponse(serviceResponse);
      }
      return responseProvider.getResponse(HttpStatus.OK, serviceResponse);
    }
    catch (ServiceRequestHandlingException e) {
      return getErrorResponseString(e.getErrorCode(), e.getMessage());
    }
  }

  private void logServiceResponse(final String serviceResponse) {
    log.trace("Service response JWS: {}", serviceResponse);
    try {
      JWSObject jwsObject = JWSObject.parse(serviceResponse);
      log.trace("Received Service response:\n{}", objectMapper.writeValueAsString(
          jwsObject.getPayload().toJSONObject()
      ));
    }
    catch (JsonProcessingException | ParseException e) {
      throw new RuntimeException(e);
    }
  }

  private void logServiceRequest(final String serviceRequest) {
    log.trace("Service request JWS: {}", serviceRequest);
    try {
      JWSObject jwsObject = JWSObject.parse(serviceRequest);
      log.trace("Sending service request:\n{}", objectMapper.writeValueAsString(
          jwsObject.getPayload().toJSONObject()
      ));
    }
    catch (JsonProcessingException | ParseException e) {
      throw new RuntimeException(e);
    }
  }

  private ResponseEntity<String> getErrorResponseString(ErrorCode errorCode, String message) {
    try {
      return responseProvider.getResponse(HttpStatus.valueOf(errorCode.getResponseCode()),
          objectMapper.writeValueAsString(ErrorResponse.builder()
              .errorCode(errorCode.name())
              .message(message)
              .build()));
    }
    catch (JsonProcessingException e) {
      throw new RuntimeException(e);
    }
  }
}
