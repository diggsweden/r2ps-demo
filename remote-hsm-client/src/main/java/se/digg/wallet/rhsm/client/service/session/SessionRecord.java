package se.digg.wallet.rhsm.client.service.session;

import java.time.Instant;

public record SessionRecord(
    String sessionId,
    String context,
    String purpose,
    Instant expiry
) {
}
