package se.digg.wallet.rhsm.client.configuration;

import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.netty.http.client.HttpClient;

import javax.net.ssl.SSLException;
import java.security.NoSuchAlgorithmException;

@Configuration
public class WebClientConfig {

  private boolean ignoreSsl = true;

  @Bean
  public WebClient webClient(WebClient.Builder webClientBuilder) throws Exception {
    HttpClient httpClient = createHttpClient();
    return webClientBuilder
        .clientConnector(new ReactorClientHttpConnector(httpClient))
        .build();
  }

  private HttpClient createHttpClient() throws SSLException, NoSuchAlgorithmException {
    if (ignoreSsl) {
      return HttpClient.create()
          .secure(sslContextSpec -> {
            try {
              sslContextSpec.sslContext(
                  SslContextBuilder.forClient()
                      .trustManager(InsecureTrustManagerFactory.INSTANCE) // Disable trust validation
                      .build()
              );
            }
            catch (SSLException e) {
              throw new RuntimeException(e);
            }
          });
    } else {
      return HttpClient.create(); // Default HttpClient with standard SSL handling
    }
  }


}
