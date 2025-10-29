package se.digg.wallet.rhsm.hsmserver.service;

import se.digg.wallet.r2ps.commons.exception.ServiceRequestException;
import se.digg.wallet.rhsm.hsmserver.configuration.KeyProviderBundle;

import java.security.PrivateKey;

public interface PrivateKeyWrapper {

  byte[] wrapKey(String kid, KeyProviderBundle kpBundle) throws ServiceRequestException;

  void generateKey(String kid, KeyProviderBundle kpBundle) throws ServiceRequestException;

  PrivateKey unwrapKey(EcKeyPairRecord keyPairRecord, String kid, KeyProviderBundle kpBundle) throws ServiceRequestException;

  void deleteKeyFromHsm(KeyCacheRecord keyCacheRecord) throws ServiceRequestException;

}
