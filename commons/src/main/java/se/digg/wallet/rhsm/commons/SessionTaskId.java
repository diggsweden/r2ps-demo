package se.digg.wallet.rhsm.commons;

import lombok.AllArgsConstructor;
import lombok.Getter;

import java.time.Duration;

@Getter
@AllArgsConstructor
public enum SessionTaskId {

  general(Duration.ofMinutes(15)),
  sign(Duration.ofSeconds(30)),
  hsm(Duration.ofMinutes(1));

  private Duration sessionDuration;
}
