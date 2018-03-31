import java.util.ArrayList;
import java.util.List;

public class Reassembler{

  private static List<AssembledTriple>  unassembledTriples;

  public Reassembler(){
    unassembledTriples = new ArrayList<AssembledTriple>();
  }

  public AssembledTriple processFragment(byte[] packet){
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
          return null;
        }
      }
      else{
        unassembledTriples.remove(at);
        boolean fin = at.addIPFrag(packet);
        if(fin){
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
