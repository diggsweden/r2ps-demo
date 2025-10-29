package se.digg.wallet.rhsm.hsmserver.configuration;

import lombok.AllArgsConstructor;
import lombok.Getter;

import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;

@Getter
@AllArgsConstructor
public enum SupportedCurve {

  P256("P-256", "secp256r1"),
  P384("P-384", "secp384r1"),
  P521("P-521", "secp521r1");

  private String id;
  private String jcaName;

  public static SupportedCurve fromId(final String id) throws NoSuchAlgorithmException {
    return Arrays.stream(values())
        .filter(v -> v.getId().equals(id))
        .findFirst()
        .orElseThrow(() -> new NoSuchAlgorithmException( "Unsupported curve: " + id));
  }

  public static List<String> toIdList() {
    return Arrays.stream(values())
        .map(SupportedCurve::getId)
        .toList();
  }

}
