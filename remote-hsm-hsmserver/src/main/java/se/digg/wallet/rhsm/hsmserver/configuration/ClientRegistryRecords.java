package se.digg.wallet.rhsm.hsmserver.configuration;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class ClientRegistryRecords {

  private List<ClientRegistryRecord> clients;

  @Data
  @NoArgsConstructor
  @AllArgsConstructor
  public static class ClientRegistryRecord {

    @JsonProperty("client-cert")
    String clientCert;
    @JsonProperty("client-id")
    String clientId;
    @JsonProperty("kid")
    String kid;
    @JsonProperty("contexts")
    List<String> contexts;
  }

}
