package se.digg.wallet.rhsm.hsmserver.configuration;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import se.digg.wallet.rhsm.hsmserver.service.KeyStoreStrategy;

import java.io.File;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.Provider;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class KeyProviderBundle {
  private String curve;
  private Provider provider;
  private KeyStore keyStore;
  private KeyPairGenerator keyPairGenerator;
  private char[] ksPassword;
  private File ksLocation;
  KeyStoreStrategy keyStoreStrategy;
}
