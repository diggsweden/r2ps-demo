package se.digg.wallet.rhsm.remotehsmbff.controller;

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
import se.digg.wallet.r2ps.commons.dto.HttpResponse;
import se.digg.wallet.r2ps.commons.dto.ServiceRequest;
import se.digg.wallet.r2ps.commons.exception.ServiceRequestHandlingException;
import se.digg.wallet.r2ps.server.service.ServiceRequestDispatcher;
import se.digg.wallet.r2ps.server.service.ServiceRequestHandler;

import java.text.ParseException;
import java.util.List;

@Slf4j
@RestController
public class ServiceController {

  private static final ObjectMapper objectMapper = StaticResources.SERVICE_EXCHANGE_OBJECT_MAPPER;

  private final ResponseProvider responseProvider;
  private final ServiceRequestHandler serviceRequestHandler;
  private final List<ServiceRequestDispatcher> requestDispatchers;

  @Autowired
  public ServiceController(final ResponseProvider responseProvider, final ServiceRequestHandler serviceRequestHandler,
      final List<ServiceRequestDispatcher> requestDispatchers) {
    this.responseProvider = responseProvider;
    this.serviceRequestHandler = serviceRequestHandler;
    this.requestDispatchers = requestDispatchers;
  }

  @PostMapping(value = "/service", produces = MediaType.APPLICATION_JSON_VALUE, consumes = MediaType.APPLICATION_JSON_VALUE)
  public ResponseEntity<String> service(@RequestBody final String serviceRequest) {
    ResponseEntity<String> dispatchedResponse = getDispatchedResponse(serviceRequest);
    if (dispatchedResponse != null) {
      return dispatchedResponse;
    }
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

  private ResponseEntity<String> getDispatchedResponse(final String serviceRequestJws) {
    try {
      JWSObject jwsObject = JWSObject.parse(serviceRequestJws);
      final ServiceRequest serviceRequest = StaticResources.TIME_STAMP_SECONDS_MAPPER
          .readValue(jwsObject.getPayload().toString(), ServiceRequest.class);

      final ServiceRequestDispatcher serviceRequestDispatcher = requestDispatchers.stream()
          .filter(dispatcher -> dispatcher.supports(serviceRequest.getContext()))
          .findFirst()
          .orElse(null);
      if (serviceRequestDispatcher != null) {
        log.debug("Request with context {} is dispatched to a service request dispatcher", serviceRequest.getContext());
        final HttpResponse dispatchResponse =
            serviceRequestDispatcher.dispatchServiceRequest(serviceRequestJws, serviceRequest.getContext());
        if (dispatchResponse.responseCode() == 200) {
          return responseProvider.getResponse(HttpStatus.OK, dispatchResponse.responseData());
        }
        else {
          return getErrorResponseString(ErrorCode.SERVICE_UNAVAILABLE,
              String.format("Service request dispatcher returned response code %d", dispatchResponse.responseCode()));
        }
      }
      return null;
    } catch (Exception e) {
      log.error("Error while dispatching service request", e);
      return getErrorResponseString(ErrorCode.SERVICE_UNAVAILABLE, e.getMessage());
    }
  }
}
