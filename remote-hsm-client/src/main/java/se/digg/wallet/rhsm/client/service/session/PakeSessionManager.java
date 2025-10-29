package se.digg.wallet.rhsm.client.service.session;

import org.springframework.stereotype.Component;
import se.digg.wallet.r2ps.client.api.impl.OpaqueR2PSClientApi;
import se.digg.wallet.r2ps.client.api.impl.OpaqueR2PSConfiguration;
import se.digg.wallet.r2ps.client.pake.opaque.ClientPakeRecord;
import se.digg.wallet.r2ps.commons.dto.payload.PakeResponsePayload;
import se.digg.wallet.r2ps.commons.dto.servicetype.SessionTask;
import se.digg.wallet.r2ps.commons.dto.servicetype.SessionTaskRegistry;
import se.digg.wallet.r2ps.commons.exception.PakeAuthenticationException;
import se.digg.wallet.r2ps.commons.exception.PakeSessionException;
import se.digg.wallet.r2ps.commons.exception.PayloadParsingException;
import se.digg.wallet.r2ps.commons.exception.ServiceRequestException;
import se.digg.wallet.r2ps.commons.exception.ServiceResponseException;
import se.digg.wallet.r2ps.commons.pake.opaque.PakeSessionRegistry;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@Component
public class PakeSessionManager {

  private static final Duration DEFAULT_MIN_TTL = Duration.ofSeconds(10);

  private final OpaqueR2PSClientApi clientApi;
  private final OpaqueR2PSConfiguration configuration;
  private final Map<String, SessionRecord> sessionMap;
  private final SessionTaskRegistry sessionTaskRegistry;

  public PakeSessionManager(final OpaqueR2PSClientApi clientApi, final OpaqueR2PSConfiguration configuration,
      final SessionTaskRegistry sessionTaskRegistry) {
    this.clientApi = clientApi;
    this.configuration = configuration;
    this.sessionTaskRegistry = sessionTaskRegistry;
    this.sessionMap = new HashMap<>();
  }

  public SessionRecord getSession(final String sessionId) throws PakeSessionException {
    purgeExpiredSessions(Duration.ZERO);
    return sessionMap.get(sessionId);
  }

  public List<SessionRecord> getAllSessions() throws PakeSessionException {
    purgeExpiredSessions(Duration.ZERO);
    return new ArrayList<>(sessionMap.values());
  }

  public SessionRecord getSession(final String context, final String purpose) throws PakeSessionException {
    purgeExpiredSessions(Duration.ZERO);
    return sessionMap.values().stream()
        .filter(sessionRecord -> sessionRecord.context().equals(context)
            && sessionRecord.purpose().equals(purpose))
        .findFirst()
        .orElse(null);
  }

  public boolean hasSession(final String context, final String purpose) throws PakeSessionException {
    return hasSession(context, purpose, DEFAULT_MIN_TTL);
  }

  public boolean hasSession(final String context, final String purpose, Duration minTtl) throws PakeSessionException {
    purgeExpiredSessions(Duration.ZERO);
    return sessionMap.values().stream()
        .anyMatch(sessionRecord -> sessionRecord.context().equals(context)
            && sessionRecord.purpose().equals(purpose)
        && Instant.now().isBefore(sessionRecord.expiry().minus(minTtl)));
  }

  public void createSession(final String pin, final String context, final String purpose)
      throws PakeAuthenticationException, PakeSessionException, ServiceResponseException, PayloadParsingException,
      ServiceRequestException, IOException {
    createSession(pin, context, purpose, DEFAULT_MIN_TTL);
  }

  public void createSession(final String pin, final String context, final String purpose, Duration minTtl)
      throws PakeAuthenticationException, PakeSessionException, ServiceResponseException, PayloadParsingException,
      ServiceRequestException, IOException {
    final PakeSessionRegistry<ClientPakeRecord> clientPakeSessionRegistry =
        configuration.getClientPakeSessionRegistry();

    // Remove all truly expired sessions
    purgeExpiredSessions(Duration.ZERO);
    final SessionRecord existingSession = getSession(context, purpose);
    // Handle existing sessions to prevent context-purpose duplication
    if (existingSession != null) {
      // A session already exists. Use it or remove it before creating a new one
      if (Instant.now().isBefore(existingSession.expiry().minus(minTtl))) {
        // A valid session exists with a sufficient lifetime. Use it.
        return;
      }
      // A session exists, but it has not enough time to live. Remove it and create a new one.
      deleteSession(existingSession.sessionId());
    }

    // Create a new session
    final SessionTask sessionTask = sessionTaskRegistry.getSessionTaskById(purpose);
    Duration requestedSessionDuration = null;
    if (sessionTask != null) {
      requestedSessionDuration = sessionTask.maxDuration();
    }
    final PakeResponsePayload sessionResponse = clientApi.createSession(pin, context, purpose, requestedSessionDuration);
    final String sessionId = sessionResponse.getPakeSessionId();
    // Synchronize client and server sessions
    final ClientPakeRecord clientSession = clientPakeSessionRegistry.getPakeSession(sessionId);
    Instant expiry = sessionResponse.getSessionExpirationTime();
    sessionMap.put(sessionId, new SessionRecord(sessionId, context, purpose, expiry));
  }

  /**
   * Deletes the session associated with the specified session ID.
   *
   * This method removes the session from the client API and the local session map.
   *
   * @param sessionId the unique identifier of the session to be deleted
   * @throws PakeSessionException if an error occurs during the session deletion process
   */
  public void deleteSession(final String sessionId) throws PakeSessionException {
    clientApi.deleteSession(sessionId);
    sessionMap.remove(sessionId);
  }

  /**
   * Deletes a specific PAKE (Password Authenticated Key Exchange) session identified
   * by the given context and purpose.
   *
   * This method retrieves the session associated with the provided context and purpose,
   * deletes it using the client API, and removes it from the session map to ensure
   * it is no longer tracked.
   *
   * @param context the context associated with the session to be deleted
   * @param purpose the purpose associated with the session to be deleted
   * @throws PakeSessionException if an error occurs during the session retrieval or deletion process
   */
  public void deleteSession(final String context, final String purpose) throws PakeSessionException {
    // There should only be one. But in case there are more, delete all sessions matching the request
    List<String> tbdSessionId = sessionMap.values().stream()
        .filter(sessionRecord -> sessionRecord.context().equals(context) && sessionRecord.purpose().equals(purpose))
        .map(SessionRecord::sessionId)
        .toList();

    for (String sessionId : tbdSessionId) {
      deleteSession(sessionId);
    }
  }

  /**
   * Deletes all active PAKE (Password Authenticated Key Exchange) sessions managed by the session map.
   *
   * This method iterates through all session records stored in the session map, deletes each session using the
   * client API, and then removes the session from the session map to ensure it is no longer tracked locally.
   *
   * @throws PakeSessionException if an error occurs during the deletion of any session
   */
  public void deleteAllSessions() throws PakeSessionException {
    for (String sessionId : new ArrayList<>(sessionMap.keySet())) {
      deleteSession(sessionId);
    }
  }

  /**
   * Removes all expired PAKE (Password Authenticated Key Exchange) sessions from the session map.
   * This is determined based on the current time and session expiry times.
   *
   * Expired sessions are permanently removed from the session storage and purged from memory.
   * The method utilizes a default minimum time-to-live (TTL) of zero when evaluating session expiration.
   *
   * @throws PakeSessionException if an error occurs while attempting to delete an expired session.
   */
  public void purgeExpiredSessions() throws PakeSessionException {
    purgeExpiredSessions(Duration.ZERO);
  }

  /**
   * Removes all expired PAKE (Password Authenticated Key Exchange) sessions from the session map,
   * based on the current time and session expiration times, with consideration of the specified minimum TTL.
   *
   * Expired sessions are permanently removed from the session storage and purged from memory if their
   * expiration time is less than the current time minus the specified minimum time-to-live.
   *
   * @param minTtl the minimum time-to-live, below which a session will be considered expired
   * @throws PakeSessionException if an error occurs while attempting to delete an expired session
   */
  public void purgeExpiredSessions(final Duration minTtl) throws PakeSessionException {
    Objects.requireNonNull(minTtl, "minTtl must not be null");
    if (minTtl.isNegative()) {
      throw new IllegalArgumentException("minTtl must not be negative");
    }
    final List<String> tbdSessions = sessionMap.values().stream()
        .filter(sessionRecord -> Instant.now().isAfter(sessionRecord.expiry().minus(minTtl)))
        .map(SessionRecord::sessionId)
        .toList();
    for (String sessionId : tbdSessions) {
      deleteSession(sessionId);
    }
  }

}
