import java.util.concurrent.atomic.AtomicBoolean;

public class Timeout implements Runnable {

  private long timeoutTime = 0;
  private AtomicBoolean timedOut;
  private AtomicBoolean incomplete;

  public Timeout(long timeoutLength, AtomicBoolean timedO, AtomicBoolean inc){
    timeoutTime = timeoutLength + System.currentTimeMillis();
  }

  public void run(){
    while(incomplete){
      if(System.currentTimeMillis() > timeoutTime){
        timedOut = true;
        return;
      }
    }
  }

}
