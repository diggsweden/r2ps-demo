package se.digg.wallet.rhsm.hsmserver.configuration;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.time.Duration;
import java.util.List;

@Data
@Configuration
@ConfigurationProperties(prefix = "rps-ops")
public class R2PSServerProperties {

  private String configLocation;
  private String serverIdentity;
  private String oprfSeed;
  private String serverOpaqueKey;
  private String serverHsmKey;
  private String clientRecordRegistryFile;
  private String clientRegistryInitDirectory;
  private Duration sessionDuration;
  private Duration finalizeDuration;
  private Duration replayCheckDuration;
  private HSMConfigurationProperties walletKeys;


  @Data
  public static class HSMConfigurationProperties {

    List<PKCS11ConfigFileProperties> pkcs11Config;
    String keystorePassword;
    String keyWrapAlias;
    String keystoreFileLocation;
    Duration hsmKeyRetensionDuration;
  }

  @Data
  public static class PKCS11ConfigFileProperties {
    private SupportedCurve curve;
    private String location;
  }

}
