import java.util.ArrayList;
import java.util.List;

public class Reassembler{

  private static List<AssembledTriple>  unassembledTriples;
  private static List<Timeout> unfinished;
  private long timeout;

  public Reassembler(long timeo){
    unassembledTriples = new ArrayList<AssembledTriple>();
    unfinished = new ArrayList<Timeout>();
    timeout = timeo;
  }

  public AssembledTriple processFragment(byte[] packet){
    //check timeouts
    for(int i = 0; i < unfinished.size(); i++){
      if(unfinished.get(i).isTimedOut){
        unfinished.get(i).complete();
        unfinished.remove(i);
        
      }
    }

    Ethernet e = new Ethernet(packet);
    String etype = e.resolveEthertype();
    if(etype.equals("ip")){
      IPPacket ip = new IPPacket(packet);
      //check IP checksum
      if(ip.getLongChecksum() != ip.getLongChecksum()){
        return new AssembledTriple(-10,-1,new byte[0]);
      }

      int ident = ip.getIp_identification();
      AssembledTriple at = searchList(ident);
      if(at == null){
        at = new AssembledTriple();
        boolean done = at.addIPFrag(packet);
        if(done){
          return at;
        }
        else{
          unassembledTriples.add(at);
          AtomicBoolean timedOut = new AtomicBoolean(false);
          AtomicBoolean incomplete = new AtomicBoolean(true);
          Timeout t = new Timeout(timeout, timedOut, incomplete, ident);
          Thread timeoutChecker = new Thread(t);
          timeoutChecker.start();
          unfinished.add(timeoutChecker);
          return null;
        }
      }
      else{
        unassembledTriples.remove(at);
        boolean fin = at.addIPFrag(packet);
        if(fin){
          for(int idx = 0; idx < unfinished.size(); idx++){
            if(at.getIdentification() == (unfinished.get(idx).getIdent())){
              unfinished.get(idx).complete();
              unfinished.remove(idx);
            }
          }
          return at;
        }
        else{
          unassembledTriples.add(at);
          return null;
        }
      }
    }
    else if(etype.equals("arp")){
      AssembledTriple at = new AssembledTriple(0, -1, packet);
      return at;
    }
    else{
      System.out.println("Unimplemented Type");
      return null;
    }
  }

  private static AssembledTriple searchList(int ident){
    for(AssembledTriple at: unassembledTriples){
      if(at.getIdentification() == ident){
        return at;
      }
    }
    return null;
  }

}
