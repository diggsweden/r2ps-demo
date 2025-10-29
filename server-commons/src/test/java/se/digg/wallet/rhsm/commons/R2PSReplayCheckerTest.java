package se.digg.wallet.rhsm.commons;

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class R2PSReplayCheckerTest {

  @Test
  void testIsReplayTest() throws Exception {

    R2PSReplayChecker replayChecker = new R2PSReplayChecker(Duration.ofMillis(200));
    assertFalse(replayChecker.isReplay("nonce1"));
    assertFalse(replayChecker.isReplay("nonce2"));
    assertTrue(replayChecker.isReplay("nonce1"));
    assertTrue(replayChecker.isReplay("nonce2"));
    Thread.sleep(200);
    assertFalse(replayChecker.isReplay("nonce1"));
    assertFalse(replayChecker.isReplay("nonce2"));
    assertTrue(replayChecker.isReplay("nonce1"));
    assertTrue(replayChecker.isReplay("nonce2"));
    assertFalse(replayChecker.isReplay("noncenew"));
  }

}
