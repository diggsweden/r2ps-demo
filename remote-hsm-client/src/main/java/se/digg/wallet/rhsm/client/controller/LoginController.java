package se.digg.wallet.rhsm.client.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.nimbusds.jose.JWSObject;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import se.digg.crypto.opaque.OpaqueUtils;
import se.digg.wallet.r2ps.client.api.ServiceResult;
import se.digg.wallet.r2ps.client.api.impl.OpaqueR2PSClientApi;
import se.digg.wallet.r2ps.commons.StaticResources;
import se.digg.wallet.r2ps.commons.dto.payload.ByteArrayPayload;
import se.digg.wallet.r2ps.commons.dto.payload.HSMParams;
import se.digg.wallet.r2ps.commons.dto.payload.JsonPayload;
import se.digg.wallet.r2ps.commons.dto.payload.ListKeysResponsePayload;
import se.digg.wallet.r2ps.commons.dto.servicetype.ServiceType;
import se.digg.wallet.r2ps.commons.exception.PakeAuthenticationException;
import se.digg.wallet.r2ps.commons.exception.PakeSessionException;
import se.digg.wallet.r2ps.commons.exception.PayloadParsingException;
import se.digg.wallet.r2ps.commons.exception.ServiceRequestException;
import se.digg.wallet.r2ps.commons.exception.ServiceResponseException;
import se.digg.wallet.rhsm.client.service.RemoteHSMSigner;
import se.digg.wallet.rhsm.client.service.session.PakeSessionManager;
import se.digg.wallet.rhsm.client.service.session.SessionDispData;
import se.digg.wallet.rhsm.client.service.session.SessionRecord;
import se.digg.wallet.rhsm.commons.Context;
import se.digg.wallet.rhsm.commons.DemoServiceType;
import se.digg.wallet.rhsm.commons.SessionTaskId;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

@Slf4j
@Controller
public class LoginController {

  private final OpaqueR2PSClientApi clientApi;
  private final PakeSessionManager sessionManager;
  private final RemoteHSMSigner hsmSigner;

  public LoginController(final OpaqueR2PSClientApi clientApi, final PakeSessionManager sessionManager,
      final RemoteHSMSigner hsmSigner) {
    this.clientApi = clientApi;
    this.sessionManager = sessionManager;
    this.hsmSigner = hsmSigner;
  }

  @RequestMapping("/")
  public String index(Model model)
      throws PakeAuthenticationException, PakeSessionException, PayloadParsingException, ServiceResponseException,
      ServiceRequestException, IOException {

    if (isLoggedIn()) {
      return "redirect:services";
    }
    return "redirect:login-page";
  }

  @RequestMapping("/login-page")
  public String loginPage(Model model) {
    return "start";
  }

  @RequestMapping("/services-page")
  public String startPage(Model model) throws PakeSessionException {
    if (!isLoggedIn()) {
      return "redirect:login-page";
    }
    model.addAttribute("sessions", getSessionDispData(sessionManager.getAllSessions()));
    return "services";
  }

  @RequestMapping("/register")
  public String register(Model model, @RequestParam(value = "pin") String pin,
      @RequestParam(value = "confirmPin") String confirmPin)
      throws PakeAuthenticationException, PakeSessionException, ServiceResponseException, ServiceRequestException {

    if (!pin.equals(confirmPin)) {
      model.addAttribute("errorMessage", "Pin and confirm pin do not match");
      return "start";
    }
    byte[] authzKey = OpaqueUtils.random(16);
    this.clientApi.deviceAuthenticatedService(DemoServiceType.REGISTER_AUTHORIZATION, new ByteArrayPayload(authzKey),
        Context.HSM);
    this.clientApi.deviceAuthenticatedService(DemoServiceType.REGISTER_AUTHORIZATION, new ByteArrayPayload(authzKey),
        Context.WALLET);
    this.clientApi.registerPin(pin, Context.HSM, authzKey);
    this.clientApi.registerPin(pin, Context.WALLET, authzKey);

    model.addAttribute("message", "Successfully registered PIN<br><br><b>Proceed to login</b>");

    return "start";
  }

  @RequestMapping("/login")
  public String login(Model model, @RequestParam(value = "pin") String pin) throws PakeSessionException {

    try {
      sessionManager.createSession(pin, Context.HSM, SessionTaskId.general.name());
      sessionManager.createSession(pin, Context.WALLET, SessionTaskId.general.name());
    }
    catch (PakeAuthenticationException | PayloadParsingException | ServiceResponseException | ServiceRequestException |
        IOException e) {
      model.addAttribute("errorMessage", "Login failed: " + e.getMessage());
      return "start";
    }
    addSessionsToModel(model);
    final List<SessionRecord> sessions = sessionManager.getAllSessions();
    return sessions.isEmpty() ? "start" : "services";
  }

  @RequestMapping("/logout")
  public String logout(Model model)
      throws PakeSessionException {
    sessionManager.deleteAllSessions();
    model.addAttribute("message", "Successfully logged out");
    return "start";
  }

  @RequestMapping("/delete-session")
  public String deleteSession(Model model, @RequestParam(value = "sessionId") String sessionId)
      throws PakeSessionException {
    sessionManager.deleteSession(sessionId);
    return "redirect:services-page";
  }

  @RequestMapping("/create-session")
  public String createSession(Model model, @RequestParam String pin, @RequestParam String context,
      @RequestParam String purpose)
      throws ServiceRequestException, IOException {
    if (!isLoggedIn()) {
      return "redirect:login-page";
    }
    try {
      sessionManager.createSession(pin, context, purpose);
    }
    catch (PakeAuthenticationException | PayloadParsingException | PakeSessionException | ServiceResponseException e) {
      model.addAttribute("errorMessage", e.getMessage());
      addSessionsToModel(model);
      return "services";
    }
    return "redirect:services-page";
  }

  private void addSessionsToModel(final Model model) {
    try {
      model.addAttribute("sessions", getSessionDispData(sessionManager.getAllSessions()));
    }
    catch (PakeSessionException e) {
      throw new RuntimeException(e);
    }
  }

  @RequestMapping("/list-keys")
  public String listKeys(Model model)
      throws PakeSessionException, ServiceRequestException, PakeAuthenticationException,
      PayloadParsingException, JsonProcessingException, ServiceResponseException {
    final SessionRecord session = sessionManager.getSession(Context.HSM, SessionTaskId.general.name());
    if (session == null) {
      return "redirect:login-page";
    }
    addSessionsToModel(model);
    final ServiceResult serviceResult =
        clientApi.userAuthenticatedService(ServiceType.HSM_LIST_KEYS, JsonPayload.builder()
                .add(HSMParams.CURVE, List.of())
                .build(),
            Context.HSM, session.sessionId());
    if (!serviceResult.success()) {
      model.addAttribute("errorMessage", getServiceRequestErrorString(serviceResult));
      return "services";
    }
    final ListKeysResponsePayload keyListPayload = serviceResult.getPayload(ListKeysResponsePayload.class);
    List<ListKeysResponsePayload.KeyInfo> keyList = keyListPayload.getKeyInfo().stream()
        .sorted(Comparator.comparing(ListKeysResponsePayload.KeyInfo::getCreationTime))
        .sorted(Comparator.comparing(ListKeysResponsePayload.KeyInfo::getCurveName))
        .toList();
    model.addAttribute("info", "Available HSM keys");
    model.addAttribute("json",
        StaticResources.SERVICE_EXCHANGE_OBJECT_MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(keyList));
    return "services";
  }

  @RequestMapping("/create-key")
  public String createKey(Model model, @RequestParam String curve)
      throws PakeSessionException, ServiceRequestException, PakeAuthenticationException,
      ServiceResponseException {
    if (!sessionManager.hasSession(Context.HSM, SessionTaskId.general.name())) {
      return "redirect:login-page";
    }
    addSessionsToModel(model);
    final ServiceResult serviceResult = clientApi.userAuthenticatedService(ServiceType.HSM_KEYGEN, JsonPayload.builder()
            .add(HSMParams.CURVE, curve)
            .build(),
        Context.HSM,
        sessionManager.getSession(Context.HSM, SessionTaskId.general.name()).sessionId());
    if (!serviceResult.success()) {
      model.addAttribute("errorMessage", getServiceRequestErrorString(serviceResult));
      return "services";
    }
    model.addAttribute("info", "Created HSM key");
    return "services";
  }

  @RequestMapping("/delete-key")
  public String deleteKey(Model model, @RequestParam String curve, @RequestParam String selectKey,
      @RequestParam(required = false) String kid)
      throws PakeSessionException, PakeAuthenticationException, ServiceResponseException, ServiceRequestException,
      PayloadParsingException {
    if (!sessionManager.hasSession(Context.HSM, SessionTaskId.general.name())) {
      return "redirect:login-page";
    }
    boolean byKid = selectKey.equals("by-id");
    addSessionsToModel(model);
    final ServiceResult serviceResult =
        clientApi.userAuthenticatedService(ServiceType.HSM_LIST_KEYS, JsonPayload.builder()
                .add(HSMParams.CURVE, List.of(curve))
                .build(),
            Context.HSM, sessionManager.getSession(Context.HSM, SessionTaskId.general.name()).sessionId());
    if (!serviceResult.success()) {
      model.addAttribute("errorMessage", getServiceRequestErrorString(serviceResult));
      return "services";
    }
    final ListKeysResponsePayload keyList = serviceResult.getPayload(ListKeysResponsePayload.class);
    final List<ListKeysResponsePayload.KeyInfo> curveKeyList = keyList.getKeyInfo().stream()
        .sorted(Comparator.comparing(ListKeysResponsePayload.KeyInfo::getCreationTime))
        .toList();
    if (curveKeyList.isEmpty()) {
      model.addAttribute("errorMessage", "No such key is available to delete");
      return "services";
    }
    ListKeysResponsePayload.KeyInfo keyToDelete = getKeyToDelete(curveKeyList, byKid, kid, selectKey);
    if (keyToDelete == null) {
      model.addAttribute("errorMessage", "No such key is available to delete");
      return "services";
    }
    final ServiceResult deleteResult =
        clientApi.userAuthenticatedService(ServiceType.HSM_DELETE_KEY, JsonPayload.builder()
            .add(HSMParams.KEY_IDENTIFIER, keyToDelete.getKid())
            .build(), Context.HSM, sessionManager.getSession(Context.HSM, SessionTaskId.general.name()).sessionId());
    if (!deleteResult.success()) {
      model.addAttribute("errorMessage", getServiceRequestErrorString(deleteResult));
      return "services";
    }
    model.addAttribute("info", String.format("Deleted HSM key for curve %s with KeyID: %s",
        curveKeyList.getFirst().getCurveName(),
        curveKeyList.getFirst().getKid()));
    return "services";
  }

  private ListKeysResponsePayload.KeyInfo getKeyToDelete(final List<ListKeysResponsePayload.KeyInfo> curveKeyList,
      final boolean byKid, final String kid, final String selectKey) {

    if (byKid) {
      return curveKeyList.stream()
          .filter(keyInfo -> keyInfo.getKid().equals(kid))
          .findFirst()
          .orElse(null);
    }
    if (curveKeyList.size() == 1) {
      // There is only one key. Ignore if the oldest or most recent is selected.
      return curveKeyList.getFirst();
    }
    return selectKey.equals("oldest")
        ? curveKeyList.getFirst()
        : curveKeyList.getLast();
  }

  @RequestMapping("/sign")
  public String sign(Model model, @RequestParam String type, @RequestParam String curve, @RequestParam String selectKey,
      @RequestParam String purpose) throws PakeSessionException, JsonProcessingException {
    log.info("Signing with type: {}, curve: {}, key: {}, purpose: {}", type, curve, selectKey, purpose);
    if (!sessionManager.hasSession(Context.HSM, SessionTaskId.general.name())) {
      return "redirect:login-page";
    }
    if (!sessionManager.hasSession(Context.HSM, purpose)) {
      model.addAttribute("errorMessage", "No such session purpose is available");
      addSessionsToModel(model);
      return "services";
    }
    addSessionsToModel(model);

    String payload = StaticResources.SERVICE_EXCHANGE_OBJECT_MAPPER.writeValueAsString(JsonPayload.builder()
        .add("payload", "Hello World")
        .build().getData());

    JWSObject signedJws;
    try {
      signedJws = hsmSigner.signJws(Context.HSM, curve, type, selectKey, purpose, payload);
    }
    catch (ServiceRequestException e) {
      model.addAttribute("errorMessage", e.getMessage());
      return "services";
    }

    model.addAttribute("info",
        "Signing with type: " + type + ", curve: " + curve + ", key: " + selectKey + ", purpose: " + purpose);
    model.addAttribute("text", signedJws.serialize());
    model.addAttribute("json", StaticResources.SERVICE_EXCHANGE_OBJECT_MAPPER.writerWithDefaultPrettyPrinter()
        .writeValueAsString(signedJws.getHeader().toJSONObject()));
    model.addAttribute("json2", StaticResources.SERVICE_EXCHANGE_OBJECT_MAPPER.writerWithDefaultPrettyPrinter()
        .writeValueAsString(signedJws.getPayload().toJSONObject()));

    return "services";
  }

  private Object getServiceRequestErrorString(final ServiceResult serviceResult) {
    return String.format("Service request error: <b>%s</b><br><br>%s", serviceResult.errorResponse().getErrorCode(),
        serviceResult.errorResponse().getMessage());
  }

  boolean isLoggedIn() {
    // Check for existing active sessions
    try {
      return sessionManager.hasSession(Context.HSM, SessionTaskId.general.name()) && sessionManager.hasSession(
          Context.WALLET, SessionTaskId.general.name());
    }
    catch (PakeSessionException e) {
      return false;
    }
  }

  List<SessionDispData> getSessionDispData(List<SessionRecord> sessions) {
    if (sessions == null) {
      return new ArrayList<>();
    }
    return sessions.stream()
        .map(SessionDispData::new)
        .sorted(Comparator.comparing(SessionDispData::getContext))
        .toList();
  }
}
