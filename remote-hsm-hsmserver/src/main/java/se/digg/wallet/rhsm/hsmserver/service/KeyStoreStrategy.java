package se.digg.wallet.rhsm.hsmserver.service;

public enum KeyStoreStrategy {
  /** Keys are permanently stored in the key store as objects */
  objects,
  /** Keys are wrapped and exported after creation and never stored as objects */
  wrapped
}
