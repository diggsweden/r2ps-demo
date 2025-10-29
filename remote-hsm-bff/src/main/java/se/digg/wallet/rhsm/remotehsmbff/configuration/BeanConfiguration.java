package se.digg.wallet.rhsm.remotehsmbff.configuration;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import org.bouncycastle.util.encoders.Hex;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.client.WebClient;
import se.digg.wallet.r2ps.commons.dto.servicetype.ServiceTypeRegistry;
import se.digg.wallet.r2ps.commons.dto.servicetype.SessionTaskRegistry;
import se.digg.wallet.r2ps.commons.pake.opaque.InMemoryPakeSessionRegistry;
import se.digg.wallet.r2ps.commons.pake.opaque.OpaqueConfiguration;
import se.digg.wallet.r2ps.commons.pake.opaque.PakeSessionRegistry;
import se.digg.wallet.r2ps.server.pake.opaque.ClientRecordRegistry;
import se.digg.wallet.r2ps.server.pake.opaque.ServerPakeRecord;
import se.digg.wallet.r2ps.server.pake.opaque.impl.FileBackedClientRecordRegistry;
import se.digg.wallet.r2ps.server.service.ClientPublicKeyRecord;
import se.digg.wallet.r2ps.server.service.ClientPublicKeyRegistry;
import se.digg.wallet.r2ps.server.service.OpaqueServiceRequestHandlerConfiguration;
import se.digg.wallet.r2ps.server.service.ServiceRequestDispatcher;
import se.digg.wallet.r2ps.server.service.impl.DefaultServiceRequestHandler;
import se.digg.wallet.r2ps.server.service.impl.FileBackedClientPublicKeyRegistry;
import se.digg.wallet.r2ps.server.service.pinauthz.impl.CodeMatchPinAuthorization;
import se.digg.wallet.r2ps.server.service.servicehandlers.OpaqueServiceHandler;
import se.digg.wallet.r2ps.server.service.servicehandlers.ServiceTypeHandler;
import se.digg.wallet.r2ps.server.service.servicehandlers.SessionServiceHandler;
import se.digg.wallet.rhsm.commons.AuthzRegistrationServiceHandler;
import se.digg.wallet.rhsm.commons.ConfigUtils;
import se.digg.wallet.rhsm.commons.Context;
import se.digg.wallet.rhsm.commons.R2PSReplayChecker;
import se.digg.wallet.rhsm.commons.SessionTaskId;
import se.digg.wallet.rhsm.remotehsmbff.service.WebClientServiceRequestDispatcher;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.bundle.CredentialBundles;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;

@Configuration
public class BeanConfiguration {

  public static final ObjectMapper YAML_MAPPER;

  static {
    YAML_MAPPER = new ObjectMapper(new YAMLFactory());
    YAML_MAPPER.setSerializationInclusion(JsonInclude.Include.NON_NULL);
    YAML_MAPPER.registerModule(new JavaTimeModule());
  }

  @Bean
  DefaultServiceRequestHandler opaqueServiceRequestHandler(
      OpaqueServiceRequestHandlerConfiguration requestHandlerConfiguration)
      throws JOSEException {
    return new DefaultServiceRequestHandler(requestHandlerConfiguration);
  }

  @Bean
  public OpaqueServiceRequestHandlerConfiguration opaqueServiceRequestHandlerConfiguration(
      CredentialBundles credentialBundles, R2PSServerProperties r2PSServerProperties,
      ServiceTypeRegistry serviceTypeRegistry, List<ServiceRequestDispatcher> serviceRequestDispatchers,
      List<ServiceTypeHandler> serviceTypeHandlerList, PakeSessionRegistry<ServerPakeRecord> serverPakeSessionRegistry,
      ClientPublicKeyRegistry clientPublicKeyRegistry) {

    final PkiCredential opaqueCredential =
        credentialBundles.getCredential(r2PSServerProperties.getServerOpaqueKey());
    final Map<String, Object> serverKeyProp =
        credentialBundles.getCredential(r2PSServerProperties.getServerOpaqueKey()).getMetadata().getProperties();
    JWSAlgorithm serverJwsAlgorithm = JWSAlgorithm.parse((String) serverKeyProp.get("jws-algorithm"));

    return OpaqueServiceRequestHandlerConfiguration.builder()
        .serverKeyPair(new KeyPair(opaqueCredential.getPublicKey(), opaqueCredential.getPrivateKey()))
        .serverJwsAlgorithm(serverJwsAlgorithm)
        .serverPakeSessionRegistry(serverPakeSessionRegistry)
        .clientPublicKeyRegistry(clientPublicKeyRegistry)
        .serviceTypeRegistry(serviceTypeRegistry)
        .serviceTypeHandlers(serviceTypeHandlerList)
        .replayChecker(new R2PSReplayChecker(r2PSServerProperties.getReplayCheckDuration()))
        .build();
  }

  @Bean ClientRecordRegistry clientRecordRegistry(R2PSServerProperties r2PSServerProperties) throws IOException {
    return new FileBackedClientRecordRegistry(ConfigUtils.getFile(r2PSServerProperties.getClientRecordRegistryFile(), true));
  }

  @Bean
  List<ServiceRequestDispatcher> serviceRequestDispatchers(R2PSServerProperties r2PSServerProperties, WebClient webClient) {
    WebClientServiceRequestDispatcher.Builder hsmDispatcherBuilder = WebClientServiceRequestDispatcher.builder(webClient);

    final Set<Map.Entry<String, String>> contextUrlConfigSet = r2PSServerProperties.getContextUrl().entrySet();
    for (Map.Entry<String, String> contextUrlEntry : contextUrlConfigSet) {
      hsmDispatcherBuilder.contextUrl(contextUrlEntry.getKey(), contextUrlEntry.getValue());
    }
    return List.of(hsmDispatcherBuilder.build());
  }

  @Bean
  ClientPublicKeyRegistry clientPublicKeyRegistry(R2PSServerProperties r2PSServerProperties) throws IOException {

    ClientPublicKeyRegistry clientPublicKeyRegistry = new FileBackedClientPublicKeyRegistry(null);

    final File clientRegistryDir = ConfigUtils.getFile(r2PSServerProperties.getClientRegistryInitDirectory());
    final File clientRegistryFile = new File(clientRegistryDir, "clients.yml");
    final ClientRegistryRecords clientRegistryRecords =
        YAML_MAPPER.readValue(clientRegistryFile, ClientRegistryRecords.class);
    final List<ClientRegistryRecords.ClientRegistryRecord> clients = clientRegistryRecords.getClients();
    for (ClientRegistryRecords.ClientRegistryRecord client : clients) {
      final File certFile = new File(new File(clientRegistryDir, "certs"), client.getClientCert());
      try (InputStream is = new FileInputStream(certFile)) {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        clientPublicKeyRegistry.registerClientPublicKey(client.getClientId(), ClientPublicKeyRecord.builder()
            .publicKey(cf.generateCertificate(is).getPublicKey())
            .supportedContexts(client.getContexts())
            .kid(client.getKid())
            .build());
      }
      catch (CertificateException e) {
        throw new RuntimeException(e);
      }
    }
    return clientPublicKeyRegistry;
  }

  @Bean
  ServiceTypeRegistry serviceTypeRegistry() {
    return ConfigUtils.getDemoServiceTypeRegistry();
  }

  @Bean
  SessionTaskRegistry sessionTaskRegistry() {
    SessionTaskRegistry sessionTaskRegistry = new SessionTaskRegistry();
    Arrays.stream(SessionTaskId.values()).forEach(sessionTaskId -> {
      sessionTaskRegistry.registerSessionTask(sessionTaskId.name(), sessionTaskId.getSessionDuration());
    });
    return sessionTaskRegistry;
  }

  @Bean
  List<ServiceTypeHandler> serviceTypeHandlerList(SessionServiceHandler sessionServiceHandler,
      ClientPublicKeyRegistry clientPublicKeyRegistry, R2PSServerProperties r2PSServerProperties,
      CredentialBundles credentialBundles, PakeSessionRegistry<ServerPakeRecord> serverPakeSessionRegistry,
      SessionTaskRegistry sessionTaskRegistry, ClientRecordRegistry clientRecordRegistry) {

    final PkiCredential opaqueCredential =
        credentialBundles.getCredential(r2PSServerProperties.getServerOpaqueKey());


    OpaqueServiceHandler opaqueServiceHandler = new OpaqueServiceHandler(
        List.of(Context.WALLET),
        new CodeMatchPinAuthorization(clientPublicKeyRegistry),
        OpaqueConfiguration.defaultConfiguration(),
        r2PSServerProperties.getServerIdentity(),
        Hex.decode(r2PSServerProperties.getOprfSeed()),
        new KeyPair(opaqueCredential.getPublicKey(), opaqueCredential.getPrivateKey()),
        serverPakeSessionRegistry,
        clientRecordRegistry,
        sessionTaskRegistry,
        Duration.ofMinutes(15),
        Duration.ofSeconds(5));

    return List.of(
        sessionServiceHandler,
        new AuthzRegistrationServiceHandler(clientPublicKeyRegistry),
        opaqueServiceHandler
    );
  }

  @Bean
  PakeSessionRegistry<ServerPakeRecord> serverPakeSessionRegistry() {
    return new InMemoryPakeSessionRegistry<>();
  }

  @Bean
  SessionServiceHandler sessionServiceHandler(PakeSessionRegistry<ServerPakeRecord> serverPakeSessionRegistry) {
    return new SessionServiceHandler(serverPakeSessionRegistry);
  }

}
