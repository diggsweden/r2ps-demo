package se.digg.wallet.rhsm.hsmserver.service;

import java.security.KeyStore;
import java.security.PrivateKey;

public record KeyCacheRecord(
    KeyStore keyStore,
    char[] pin,
    String alias,
    PrivateKey privateKey
) {
}
