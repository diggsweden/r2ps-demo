package se.digg.wallet.rhsm.commons;

import lombok.extern.slf4j.Slf4j;
import se.digg.wallet.r2ps.server.service.ReplayChecker;

import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

@Slf4j
public class R2PSReplayChecker implements ReplayChecker {

  private final Duration replayCheckDuration;
  //private final List<String> allowedContexts;
  private final Map<String, Instant> nonceMap;

  public R2PSReplayChecker(final Duration replayCheckDuration) {
    this.replayCheckDuration = replayCheckDuration;
    //this.allowedContexts = List.of();
    this.nonceMap = new HashMap<>();
  }

/*
  public RpsOpsReplayChecker(final Duration replayCheckDuration, final List<String> allowedContexts) {
    this.replayCheckDuration = replayCheckDuration;
    this.allowedContexts = Optional.ofNullable(allowedContexts).orElse(List.of());
    this.nonceMap = new HashMap<>();
  }
*/

  @Override
  public boolean isReplay(final String nonce) {
    // Remove expired nonces from noncemap
    nonceMap.entrySet().removeIf(entry -> Instant.now().isAfter(entry.getValue().plus(replayCheckDuration)));
    // Replay check
/*
    if (!allowedContexts.isEmpty()) {
      log.debug("Checking context {} against allowed replay contexts {}", context, allowedContexts);
      if (!this.allowedContexts.contains(context)) {
        log.debug("Context {} not allowed, treating this as replay", context);
        return true;
      }
    }
*/
    // Check if this is a replay
    boolean replay = nonceMap.containsKey(nonce);
    // Store this instance in the replay map
    nonceMap.put(nonce, Instant.now());
    // Return replay indication
    return replay;
  }
}
