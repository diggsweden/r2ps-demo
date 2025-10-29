package se.digg.wallet.rhsm.hsmserver;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.security.Security;

@SpringBootApplication
public class RemoteHsmHsmserverApplication {

  static {
    Security.addProvider(new BouncyCastleProvider());
  }
  public static void main(String[] args) {
    SpringApplication.run(RemoteHsmHsmserverApplication.class, args);
  }

}
