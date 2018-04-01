import java.util.concurrent.atomic.AtomicBoolean;

public class Timeout implements Runnable {

  private int identification;
  private long timeoutTime = 0;
  private AtomicBoolean timedOut;
  private AtomicBoolean incomplete;

  public Timeout(long timeoutLength, AtomicBoolean timedO, AtomicBoolean inc, int id){
    timeoutTime = timeoutLength + System.currentTimeMillis();
    timedOut = timedO;
    incomplete = inc;
    identification = id;
  }

  public void run(){
    while(incomplete.get()){
      if(System.currentTimeMillis() > timeoutTime){
        timedOut.set(true);
        return;
      }
    }
    return;
  }

  public boolean isTimedOut(){
    return timedOut.get();
  }

  public void complete(){
    incomplete.set(false);
  }

  public int getIdent(){
    return identification;
  }
}
