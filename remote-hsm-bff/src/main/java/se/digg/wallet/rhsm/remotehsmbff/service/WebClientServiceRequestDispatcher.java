package se.digg.wallet.rhsm.remotehsmbff.service;

import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.client.WebClient;
import se.digg.wallet.r2ps.commons.dto.ErrorCode;
import se.digg.wallet.r2ps.commons.dto.HttpResponse;
import se.digg.wallet.r2ps.commons.exception.ServiceRequestHandlingException;
import se.digg.wallet.r2ps.server.service.ServiceRequestDispatcher;

import java.util.HashMap;
import java.util.Map;

@Slf4j
public class WebClientServiceRequestDispatcher implements ServiceRequestDispatcher {

  @Getter
  @Setter
  private Map<String, String> contextUrlMap;
  private final WebClient webClient;

  public WebClientServiceRequestDispatcher(WebClient webClient) {
    this.contextUrlMap = new HashMap<>();
    this.webClient = webClient;
  }

  @Override
  public HttpResponse dispatchServiceRequest(final String serviceRequest, String context)
      throws ServiceRequestHandlingException {
    String url = contextUrlMap.get(context);
    if (url == null) {
      throw new ServiceRequestHandlingException(String.format("No dispatch URL registered for context %s", context),
          ErrorCode.SERVICE_UNAVAILABLE);
    }
    log.debug("Sending service request to {}", url);
    return webClient.post()
        .uri(url)
        .bodyValue(serviceRequest)
        .header("Content-Type", MediaType.APPLICATION_JSON_VALUE)
        .exchangeToMono(response -> response.toEntity(String.class))
        .map(entity -> new HttpResponse(
            entity.getBody(),
            entity.getStatusCode().value()
        ))
        .block();
  }

  @Override
  public boolean supports(final String context) {
    return contextUrlMap.containsKey(context);
  }

  public static Builder builder(WebClient webClient) {
    return new Builder(webClient);
  }

  public static class Builder {

    private final WebClientServiceRequestDispatcher dispatcher;

    public Builder(WebClient webClient) {
      this.dispatcher = new WebClientServiceRequestDispatcher(webClient);
    }

    public Builder contextUrlMap(final Map<String, String> contextUrlMap) {
      this.dispatcher.setContextUrlMap(contextUrlMap);
      return this;
    }

    public Builder contextUrl(final String context, final String url) {
      this.dispatcher.getContextUrlMap().put(context, url);
      return this;
    }

    public WebClientServiceRequestDispatcher build() {
      return this.dispatcher;
    }

  }
}
