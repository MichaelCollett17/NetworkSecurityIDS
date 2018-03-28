import java.util.ArrayList;


public class AssembledTriple{
  final int arp = 0;//zero, arp, one packet list
  final int correct = 1;//one, reassembled packet, list of frags
  final int correct_overlap = 2;//two, reassembled packet, list of frags
  final int oversized = 3;//three, first packet, list of ALL frags
  final int timedout = 4;//four, first segment, list of all parially processed segments

  private int identification;
  private int sid;
  private byte[] assembledPacket;
  private ArrayList<byte[]> fragments = new ArrayList<byte[]>();

  //ONLY USED FOR IP
  public AssembledTriple(){
    identification = -2;
    sid = -1;
    assembledPacket = null;
  }

  //only used for arp
  public AssembledTriple(int s, int ident, byte[] packet){
    identification = ident;
    sid = s;
    assembledPacket = packet;
    fragments.add(packet);
  }

  public boolean addIPFrag(byte[] packet){
    //add frag logic
    return false;
  }

  public int getIdentification(){
    return identification;
  }

  public void setIdentification(int ident){
    this.identification = ident;
  }

  public int getSID(){
    return sid;
  }

  public void setSID(int s){
    this.sid = s;
  }

  public byte[] getAssembledPacket(){
    return assembledPacket;
  }

  public void setAssembledPacket(byte[] p){
    this.assembledPacket = p;
  }

  public ArrayList<byte[]> getFragments(){
    return fragments;
  }

  public void setFragments(ArrayList<byte[]> frags){
    this.fragments = frags;
  }

}
