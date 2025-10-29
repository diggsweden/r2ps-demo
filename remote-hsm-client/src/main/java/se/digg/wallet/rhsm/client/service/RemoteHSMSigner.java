package se.digg.wallet.rhsm.client.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import io.netty.util.Mapping;
import org.springframework.stereotype.Component;
import se.digg.wallet.r2ps.client.api.ServiceResult;
import se.digg.wallet.r2ps.client.api.impl.OpaqueR2PSClientApi;
import se.digg.wallet.r2ps.client.jws.HSECPkdsSigner;
import se.digg.wallet.r2ps.client.jws.RemoteHsmECDSASigner;
import se.digg.wallet.r2ps.client.jws.pkds.HSPKDSAlgorithm;
import se.digg.wallet.r2ps.client.jws.pkds.PKDSHeaderParam;
import se.digg.wallet.r2ps.client.jws.pkds.PKDSPublicKey;
import se.digg.wallet.r2ps.client.jws.pkds.PKDSSuite;
import se.digg.wallet.r2ps.client.jws.pkds.impl.RemoteHsmPKDSKeyDerivation;
import se.digg.wallet.r2ps.commons.dto.payload.HSMParams;
import se.digg.wallet.r2ps.commons.dto.payload.JsonPayload;
import se.digg.wallet.r2ps.commons.dto.payload.ListKeysResponsePayload;
import se.digg.wallet.r2ps.commons.dto.servicetype.ServiceType;
import se.digg.wallet.r2ps.commons.exception.PakeAuthenticationException;
import se.digg.wallet.r2ps.commons.exception.PakeSessionException;
import se.digg.wallet.r2ps.commons.exception.PayloadParsingException;
import se.digg.wallet.r2ps.commons.exception.ServiceRequestException;
import se.digg.wallet.r2ps.commons.exception.ServiceResponseException;
import se.digg.wallet.rhsm.client.service.session.PakeSessionManager;
import se.digg.wallet.rhsm.client.service.session.SessionRecord;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;

@Component
public class RemoteHSMSigner {
  
  OpaqueR2PSClientApi clientApi;
  PakeSessionManager sessionManager;
  
  public RemoteHSMSigner(OpaqueR2PSClientApi clientApi, PakeSessionManager sessionManager) {
    this.clientApi = clientApi;
    this.sessionManager = sessionManager;
  }
  
  public JWSObject signJws(String context, String curve, String type, String selectKey, String purpose, String payload)
      throws ServiceRequestException {

    try {
      if (!sessionManager.hasSession(context, purpose)) {
        throw new PakeSessionException("No session found for context " + context + " and purpose " + purpose);
      }
      final SessionRecord session = sessionManager.getSession(context, purpose);
      // Get key
      final ServiceResult serviceResult =
          clientApi.userAuthenticatedService(ServiceType.HSM_LIST_KEYS, JsonPayload.builder()
                  .add(HSMParams.CURVE, List.of(curve))
                  .build(), context,
              session.sessionId());
      if (!serviceResult.success()) {
        throw new ServiceRequestException("Unable to list keys for context " + context + " and purpose " + purpose);
      }
      final ListKeysResponsePayload listKeysResponse = serviceResult.getPayload(ListKeysResponsePayload.class);
      final List<ListKeysResponsePayload.KeyInfo> keyList = listKeysResponse.getKeyInfo();
      if (keyList.isEmpty()) {
        throw new ServiceRequestException("No keys found for context " + context + " and purpose " + purpose);
      }
      final List<ListKeysResponsePayload.KeyInfo> sortedKeys = keyList.stream()
          .sorted(Comparator.comparing(ListKeysResponsePayload.KeyInfo::getCreationTime))
          .toList();
      ListKeysResponsePayload.KeyInfo selectedKey = selectKey.equals("oldest") ? sortedKeys.getFirst() : sortedKeys.getLast();
      return switch (type) {
        case "ECDSA" -> ecdsaSign(curve, selectedKey, payload, session, context);
        case "HS256-PKDS", "HS384-PKDS", "HS512-PKDS" -> hspkdsSign(type, curve, selectedKey, payload, session, context);
        default -> throw new IllegalStateException("Unsupported Signature Type: " + type);
      };
    }
    catch (PakeAuthenticationException | PakeSessionException | PayloadParsingException | ServiceResponseException |
        GeneralSecurityException | JsonProcessingException | JOSEException e) {
      throw new ServiceRequestException("Failed to process sign request: " + e.getMessage(), e);
    }
  }

  private JWSObject hspkdsSign(final String type, String curve, final ListKeysResponsePayload.KeyInfo selectedKey, final String payload, final SessionRecord session, final String context)
      throws GeneralSecurityException, JOSEException {

    KeyPair recipientKeyPair = generateEcKeyPair(curve);
    JWK recipientJwk = getJWKfromPublicKey(recipientKeyPair.getPublic());
    JWK producerJwk = getJWKfromPublicKey(selectedKey.getPublicKey());

    final PKDSHeaderParam pkdsParam = PKDSHeaderParam.builder()
        .suite(PKDSSuite.ECDH_HKDF_SHA256)
        .recipientPublicKey(PKDSPublicKey.builder()
            .jwk(recipientJwk)
            .build())
        .producerPublicKey(PKDSPublicKey.builder()
            .jwk(producerJwk)
            .build())
        .build();

    HSPKDSAlgorithm hspkdsAlgorithm = HSPKDSAlgorithm.fromString(type);
    JWSSigner signer = new HSECPkdsSigner(hspkdsAlgorithm,
        new RemoteHsmPKDSKeyDerivation(clientApi, context, selectedKey.getKid(), session.sessionId()));

    JWSHeader jwsHeader = new JWSHeader.Builder(hspkdsAlgorithm.getAlg())
        .customParam(HSECPkdsSigner.PKDS_HEADER_PARAM, pkdsParam.toJsonObject())
        .build();
    JWSObject jwsObject = new JWSObject(jwsHeader, new Payload(payload));
    jwsObject.sign(signer);
    return jwsObject;
  }

  private JWSObject ecdsaSign(String curve, final ListKeysResponsePayload.KeyInfo selectedKey, final String payload, final SessionRecord session, final String context)
      throws ServiceRequestException, JsonProcessingException, JOSEException {
    JWSAlgorithm alg = switch (curve) {
      case "P-256" -> JWSAlgorithm.ES256;
      case "P-384" -> JWSAlgorithm.ES384;
      case "P-521" -> JWSAlgorithm.ES512;
      default -> throw new ServiceRequestException("Unsupported Curve: " + curve);
    };
    JWSSigner signer = new RemoteHsmECDSASigner(clientApi, context, selectedKey.getKid(), alg, session.sessionId());
    JWSHeader jwsHeader = new JWSHeader.Builder(alg)
        .keyID(selectedKey.getKid())
        .build();
    JWSObject jwsObject = new JWSObject(jwsHeader, new Payload(payload));
    jwsObject.sign(signer);
    return jwsObject;
  }

  public static KeyPair generateEcKeyPair(String curveName) throws GeneralSecurityException {
    String jcaCurve = normalizeCurveName(curveName);
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
    kpg.initialize(new ECGenParameterSpec(jcaCurve), SecureRandom.getInstanceStrong());
    return kpg.generateKeyPair();
  }

  private static String normalizeCurveName(String name) {
    String n = name.trim().toUpperCase(Locale.ROOT).replace("-", "");
    return switch (n) {
      case "P256", "SECP256R1", "PRIME256V1" -> "secp256r1";
      case "P384", "SECP384R1" -> "secp384r1";
      case "P521", "SECP521R1" -> "secp521r1";
      default -> name; // assume it's already a valid JCA curve name
    };
  }


    /**
     * Converts a given public key into a JSON Web Key (JWK) representation.
     *
     * @param publicKey the public key to convert, which can be either an RSA or EC public key
     * @return the JWK representation of the given public key
     * @throws NoSuchAlgorithmException if the type of the provided public key is not supported
     */
  public static JWK getJWKfromPublicKey(PublicKey publicKey)
      throws NoSuchAlgorithmException {
    if (publicKey instanceof RSAPublicKey) {
      return new RSAKey.Builder((RSAPublicKey) publicKey).build();
    }
    if (publicKey instanceof ECPublicKey ecPublicKey) {
      ECParameterSpec params = ecPublicKey.getParams();
      return new ECKey.Builder(
          Curve.forECParameterSpec(params),
          (ECPublicKey) publicKey).build();
    }
    throw new NoSuchAlgorithmException("Public key type not supported");
  }


}
