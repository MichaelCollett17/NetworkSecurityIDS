import java.util.ArrayList;


public class AssembledTriple{
  final int arp = 0;//zero, arp, one packet list
  final int correct = 1;//one, reassembled packet, list of frags
  final int correct_overlap = 2;//two, reassembled packet, list of frags
  final int oversized = 3;//three, first packet, list of ALL frags
  final int timedout = 4;//four, first segment, list of all parially processed segments

  private ArrayList<Integer> holes = new ArrayList<Integer>();
  private int identification;
  private int sid;
  private byte[] assembledPacket;
  private ArrayList<byte[]> fragments = new ArrayList<byte[]>();
  private boolean overwrote = false;
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

  //preference to overwriting new data (like linux)
  public boolean addIPFrag(byte[] packet){
    //delete this!
    //SimplePacketDriver driver=new SimplePacketDriver();

    IPPacket ip = new IPPacket(packet);
    setIdentification(ip.getIp_identification());
    this.fragments.add(packet);
    int length = ip.getIp_length() + 14;//14 for ethernet header
    if(assembledPacket == null){
      assembledPacket = new byte[length];
      //set a value = index for each of the holes
      for(int i = 0; i < length; i++){
        holes.add(i);
      }
    }
    int ethAndHeaderLen = 14 + (ip.getIp_IHL()*4); //14 eth header + IHL*4 for ip header
    System.out.println("EthandHead:"+ethAndHeaderLen);
    int packetIndex;
    for(packetIndex = 0; packetIndex < ethAndHeaderLen; packetIndex++){
      assembledPacket[packetIndex] = packet[packetIndex];
      Integer i = new Integer(packetIndex);
      holes.remove(i);
    }
    int offset = ip.getIp_fragmentOffset() * 8;
    int packetEnd = (packet.length) + offset;
    //This accounts for Ethernet Padding! why the heck is padding inconsistent??
    //need to check this with papa before submission
    if((packetEnd == 60) && (length < 60)){
      packetEnd = length;//ignore padding
    }
    //System.out.println("Length:    " + length + "\noffset:    " + offset
    //  + "\npacketend: " + packetEnd+ "\npacketLen: "+ packet.length);
    //System.out.println(driver.byteArrayToString(packet));
    for(int idx= offset + ethAndHeaderLen; idx < packetEnd; idx++){
      assembledPacket[idx] = packet[packetIndex];
      Integer i = new Integer(idx);
      holes.remove(i);
      packetIndex++;
    }
    //System.out.println("Holes:     " + holes.size() + "\n***********");
    if(holes.size() == 0){
      if(overwrote){
          setSID(correct_overlap);
      }
      else if(getSID() == -1){
        setSID(correct);
      }
      return true;
    }
    else{
      return false;
    }
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
