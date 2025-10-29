package se.digg.wallet.rhsm.client.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import se.digg.wallet.r2ps.client.api.ServiceExchangeConnector;
import se.digg.wallet.r2ps.commons.dto.HttpResponse;
import se.digg.wallet.rhsm.client.configuration.R2PSClientProperties;

@Slf4j
@Component
public class ClientServiceConnector implements ServiceExchangeConnector {

  private final WebClient webClient;
  @Autowired
  R2PSClientProperties prop;

  @Autowired
  public ClientServiceConnector(final WebClient webClient) {
    this.webClient = webClient;
    
  }

  @Override
  public HttpResponse requestService(final String serviceRequest) {
    String url = prop.getServerUrl() + prop.getServicePath();
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
}
