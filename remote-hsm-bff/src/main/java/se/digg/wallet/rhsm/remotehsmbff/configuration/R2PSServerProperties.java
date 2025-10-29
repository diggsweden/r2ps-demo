package se.digg.wallet.rhsm.remotehsmbff.configuration;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.time.Duration;
import java.util.Map;

@Data
@Configuration
@ConfigurationProperties(prefix = "rps-ops")
public class R2PSServerProperties {

  private String serverIdentity;
  private String oprfSeed;
  private String serverOpaqueKey;
  private String serverHsmKey;
  private String clientRecordRegistryFile;
  private String clientRegistryInitDirectory;
  private Duration sessionDuration;
  private Duration finalizeDuration;
  private Duration replayCheckDuration;
  private Map<String, String> contextUrl;
}
