

public class AssembledTriple{
  final int arp = 0;//zero, arp, one packet list
  final int correct = 1;//one, reassembled packet, list of frags
  final int correct_overlap = 2;//two, reassembled packet, list of frags
  final int oversized = 3;//three, first packet, list of ALL frags
  final int correct = 4;//four, first segment, list of all parially processed segments

  private int identification;
  private int sid;
  private IPPacket assembledPacket;
  private ArrayList<IPPacket> fragments;

  public AssembledTriple(){

  }

}
