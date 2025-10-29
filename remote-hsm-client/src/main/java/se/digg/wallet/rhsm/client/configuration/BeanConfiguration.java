package se.digg.wallet.rhsm.client.configuration;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import se.digg.wallet.r2ps.client.api.ServiceExchangeConnector;
import se.digg.wallet.r2ps.client.api.impl.OpaqueR2PSClientApi;
import se.digg.wallet.r2ps.client.api.impl.OpaqueR2PSConfiguration;
import se.digg.wallet.r2ps.client.pake.opaque.ClientPakeRecord;
import se.digg.wallet.r2ps.commons.dto.servicetype.ServiceTypeRegistry;
import se.digg.wallet.r2ps.commons.dto.servicetype.SessionTaskRegistry;
import se.digg.wallet.r2ps.commons.pake.opaque.InMemoryPakeSessionRegistry;
import se.digg.wallet.r2ps.commons.pake.opaque.PakeSessionRegistry;
import se.digg.wallet.rhsm.commons.ConfigUtils;
import se.digg.wallet.rhsm.commons.SessionTaskId;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.bundle.CredentialBundles;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Arrays;
import java.util.Map;

@Slf4j
@Configuration
public class BeanConfiguration {

  @Bean
  public OpaqueR2PSClientApi rpsOpsClientApi(OpaqueR2PSConfiguration configuration) {
    return new OpaqueR2PSClientApi(configuration);
  }

  @Bean
  public OpaqueR2PSConfiguration rpsOpsConfiguration(R2PSClientProperties prop,
      CredentialBundles credentialBundles, ServiceExchangeConnector connector, ServiceTypeRegistry serviceTypeRegistry,
      PakeSessionRegistry<ClientPakeRecord> clientPakeSessionRegistry) {

    final OpaqueR2PSConfiguration.Builder builder = OpaqueR2PSConfiguration.builder()
        .clientIdentity(prop.getClientIdentity())
        .contextSessionDuration(prop.getSessionDuration())
        .serviceExchangeConnector(connector)
        .serviceTypeRegistry(serviceTypeRegistry)
        .clientPakeSessionRegistry(clientPakeSessionRegistry);

    final Map<String, R2PSClientProperties.ContextParams> contexts = prop.getContexts();
    for (Map.Entry<String, R2PSClientProperties.ContextParams> context : contexts.entrySet()) {
      addContext(credentialBundles, builder, context);
    }

    return builder.build();

  }

  @Bean
  PakeSessionRegistry<ClientPakeRecord> clientPakeRecordPakeSessionRegistry() {
    return new InMemoryPakeSessionRegistry<>();
  }

  @Bean ServiceTypeRegistry serviceTypeRegistry() {
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

  private void addContext(final CredentialBundles credentialBundles, final OpaqueR2PSConfiguration.Builder builder,
      final Map.Entry<String, R2PSClientProperties.ContextParams> context) {
    final PkiCredential credential = credentialBundles.getCredential(context.getValue().getKey());
    final Map<String, Object> properties = credential.getMetadata().getProperties();
    final String keyId = credential.getMetadata().getKeyId();
    JWSAlgorithm jwsAlgorithm = JWSAlgorithm.parse((String) properties.get("jws-algorithm"));
    final File certfile = ConfigUtils.getFile(context.getValue().getServerCertificateLocation());
    try (InputStream is = new FileInputStream(certfile)) {
      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      builder.addContext(context.getKey(), keyId, new KeyPair(credential.getPublicKey(), credential.getPrivateKey()),
          jwsAlgorithm, context.getValue().getServerIdentity(), cf.generateCertificate(is).getPublicKey());
    }
    catch (IOException | CertificateException | JOSEException e) {
      throw new RuntimeException(e);
    }
  }

}
