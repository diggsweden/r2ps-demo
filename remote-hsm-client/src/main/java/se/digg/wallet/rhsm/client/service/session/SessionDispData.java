package se.digg.wallet.rhsm.client.service.session;

import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

@Data
@NoArgsConstructor
public class SessionDispData {
  private String sessionId;
  private String context;
  private String purpose;
  private String expires;

  public SessionDispData(SessionRecord session) {
    this.sessionId = session.sessionId();
    this.context = session.context();
    this.purpose = session.purpose();
    this.expires =
        session.expiry().atZone(ZoneId.systemDefault()).format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
  }
}
