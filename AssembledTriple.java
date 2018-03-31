import java.util.ArrayList;


public class AssembledTriple{
  final int arp = 0;//zero, arp, one packet list
  final int correct = 1;//one, reassembled packet, list of frags
  final int correct_overlap = 2;//two, reassembled packet, list of frags
  final int oversized = 3;//three, first packet, list of ALL frags
  final int timedout = 4;//four, first segment, list of all parially processed segments

  //private ArrayList<Integer> holes = new ArrayList<Integer>();
  private ArrayList<HoleDescriptor> holes = new ArrayList<HoleDescriptor>();
  private int identification;
  private int sid;
  private byte[] assembledPacket;
  private ArrayList<byte[]> fragments = new ArrayList<byte[]>();
  private boolean overwrote = false;
  private int assembledLength = 0;
  private boolean first = true;

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
    IPPacket ip = new IPPacket(packet);
    this.fragments.add(packet);
    int totalLength = ip.getIp_length() + 14;//14 for ethernet header
    int dataLength = ip.getIp_length() - (ip.getIp_IHL() * 4);
    int offset = (ip.getIp_fragmentOffset() * 8) + 14 + (ip.getIp_IHL() * 4);//frag first
    int fragFirst = offset;//first val for data
    int fragLast = offset + dataLength;//last val for data
    boolean mf = ip.isIp_MFflag();//0=last frag

    //make hole descriptor class, follow algorithm, size based on last frags (offset*3 + dataLength)
    if(first){//if first packet
      first = false;
      setIdentification(ip.getIp_identification());
      HoleDescriptor initialHole = new HoleDescriptor((14 + (ip.getIp_IHL() * 4)), 2000000);
      holes.add(initialHole);
    }

    if(!mf){
      //set assembledPacket Length
      assembledPacket = new byte[fragLast];
      //take all frags and write em
      writeFrags();
    }
    else{
      if(assembledPacket != null){
        //write to assembledpacket
        for(int index = offset+14; index < offset+totalLength; index++){
          assembledPacket[index] = packet[index];
        }
      }
    }

    //hole handling alorithm based upon rfc815
    for(int i = 0; i < holes.size(); i++){
      HoleDescriptor hole = holes.get(i);
      if((fragFirst > hole.getLast()) || (fragLast < hole.getFirst())){
      }
      else{
        holes.remove(i);
        System.out.println("********\nMF: " + mf + "\nholefirst: " + hole.getFirst()
          + "\nHoleLast: " + hole.getLast() + "\nFragLast " + fragLast +
          "\nFragFirst: " + fragFirst + assembledPacket);
        if(fragFirst > hole.getFirst()){
          System.out.println("a");
          holes.add(new HoleDescriptor(hole.getFirst(), fragFirst));
        }
        if((fragLast < hole.getLast()) && mf){
          System.out.println("b");
          holes.add(new HoleDescriptor(fragLast + 1, hole.getLast()));
        }
        if(holes.size() == 0){
          System.out.println("c");
          if(overwrote){
            setSID(correct_overlap);
          } else{
            setSID(correct);
          }
          return true;
        }
      }
    }
    return false;
  }

  public void writeFrags(){
    for(int idx = 0; idx < fragments.size(); idx ++){
      byte[] packet = fragments.get(idx);
      IPPacket ip = new IPPacket(packet);
      int totalLength = ip.getIp_length() + 14;//14 for ethernet header
      int headerLength = 14 + (ip.getIp_IHL() * 4);
      int packetIndex = headerLength;
      int dataLength = ip.getIp_length() - (ip.getIp_IHL() * 4);
      int offset = (ip.getIp_fragmentOffset() * 8) + 14 + (ip.getIp_IHL() * 4);//frag first
      //first guy writes header
      if(idx == 0){
        for(int i = 0; i < headerLength; i++)
          assembledPacket[i] = packet[i];
      }

      if(ip.get_Ip_fragmentOffset() == 1){
        System.out.println("WARNING: Offset of 1\nThis may");
      }
      //write data for all of them
      System.out.println(offset);
      System.out.println(offset+dataLength);
      System.out.println(assembledPacket.length);
      for(int index = offset; index < offset+dataLength; index++){
        assembledPacket[index] = packet[headerLength];
        headerLength++;
      }
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
