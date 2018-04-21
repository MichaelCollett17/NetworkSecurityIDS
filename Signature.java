
public class Signature{
  private String rule = "";
  private String logFile = "";

  public Signature(String r){
    this.rule = r;
    System.out.println(rule);
  }

  public void compare(IPPacket ip){

  }

  public void compare(ARP arp){

  }

  public void compare(TCP tcp){

  }

  public void compare(UDP udp){

  }

  public void compare(ICMP icmp){

  }

//use many methods as most code is the same

}
