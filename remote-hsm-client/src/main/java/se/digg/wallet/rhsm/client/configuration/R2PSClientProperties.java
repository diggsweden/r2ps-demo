package se.digg.wallet.rhsm.client.configuration;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.time.Duration;
import java.util.Map;

@Data
@Configuration
@ConfigurationProperties(prefix = "rps-ops-client")
public class R2PSClientProperties {

  private String clientIdentity;
  private Map<String, ContextParams> contexts;
  private Duration sessionDuration;
  private String serverUrl;
  private String servicePath;

  @Data
  @NoArgsConstructor
  @AllArgsConstructor
  public static class ContextParams {
    private String key;
    private String serverIdentity;
    private String serverCertificateLocation;
  }

}
