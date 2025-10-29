package se.digg.wallet.rhsm.client.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import se.digg.wallet.r2ps.client.api.ServiceResult;
import se.digg.wallet.r2ps.client.api.impl.OpaqueR2PSClientApi;
import se.digg.wallet.r2ps.commons.dto.payload.ByteArrayPayload;
import se.digg.wallet.r2ps.commons.dto.payload.PakeResponsePayload;
import se.digg.wallet.r2ps.commons.exception.PakeAuthenticationException;
import se.digg.wallet.r2ps.commons.exception.PakeSessionException;
import se.digg.wallet.r2ps.commons.exception.ServiceRequestException;
import se.digg.wallet.r2ps.commons.exception.ServiceResponseException;
import se.digg.wallet.rhsm.commons.Context;
import se.digg.wallet.rhsm.commons.DemoServiceType;

@Slf4j
@Controller
public class TestController {

  private final OpaqueR2PSClientApi clientApi;

  @Autowired
  public TestController(final OpaqueR2PSClientApi clientApi) {
    this.clientApi = clientApi;
  }

  @RequestMapping("/test")
  public String test(Model model) {
    return "test";
  }

  @RequestMapping("/login-hsm")
  public String loginHsm(Model model) {

    try {
      final PakeResponsePayload sessionResponse = clientApi.createSession("1234", Context.HSM);
      String sessionId = sessionResponse.getPakeSessionId();
      log.info("Created session for hsm context: {}", sessionId);
    }
    catch (PakeSessionException | PakeAuthenticationException | ServiceResponseException e) {
      throw new RuntimeException(e);
    }

    return "test";
  }

  @RequestMapping("/login-wallet")
  public String loginWallet(Model model) {

    try {
      final PakeResponsePayload sessionResponse = clientApi.createSession("1234", Context.WALLET);
      String sessionId = sessionResponse.getPakeSessionId();
      log.info("Created session for wallet context: {}", sessionId);
    }
    catch (PakeSessionException | PakeAuthenticationException | ServiceResponseException e) {
      throw new RuntimeException(e);
    }

    return "test";
  }

  @RequestMapping("/register-pin-hsm")
  public String registerPinHsm(Model model)
      throws PakeAuthenticationException, PakeSessionException, ServiceResponseException, ServiceRequestException {
    final ServiceResult autzRegResult = clientApi.deviceAuthenticatedService(DemoServiceType.REGISTER_AUTHORIZATION,
        new ByteArrayPayload("authz1234".getBytes()), Context.HSM);
    if (autzRegResult.success()) {
      log.debug("Successfully set authorization code - {}", "authz1234");
    } else {
      log.error("Failed to set authorization code - {}", "authz1234");
      model.addAttribute("error", "Failed to set authorization code");
      return "test";
    }
    try {
      clientApi.registerPin("1234", "hsm","authz1234".getBytes());
    }
    catch (PakeSessionException | PakeAuthenticationException e) {
      log.error("Failed to register PIN", e);
      throw new RuntimeException(e);
    }
    return "test";
  }

  @RequestMapping("/register-pin-wallet")
  public String registerPinWallet(Model model)
      throws PakeAuthenticationException, PakeSessionException, ServiceResponseException, ServiceRequestException {

    final ServiceResult autzRegResult = clientApi.deviceAuthenticatedService(DemoServiceType.REGISTER_AUTHORIZATION,
        new ByteArrayPayload("authz1234".getBytes()), Context.WALLET);

    if (autzRegResult.success()) {
      log.debug("Successfully set authorization code - {}", "authz1234");
    } else {
      log.error("Failed to set authorization code - {}", "authz1234");
      model.addAttribute("error", "Failed to set authorization code");
      return "test";
    }
    try {
      clientApi.registerPin("1234", "wallet","authz1234".getBytes());
    }
    catch (PakeSessionException | PakeAuthenticationException e) {
      log.error("Failed to register PIN", e);
      throw new RuntimeException(e);
    }
    return "test";
  }

}
