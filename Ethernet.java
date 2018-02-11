import java.util.Arrays;
public class Ethernet {
  private byte[] packet;
  private byte[] destinationMac;
  private byte[] sourceMac;
  private byte[] ethertype;

  public Ethernet(byte[] packet_){
    this.packet = packet_;
    setDestinationMac(Arrays.copyOfRange(packet_,0,6));
    setSourceMac(Arrays.copyOfRange(packet_,6,6));
    setEthertype(Arrays.copyOfRange(packet_,12,2));
  }

  public void setDestinationMac(byte[] dest){
    destinationMac = dest;
  }

  public byte[] getDestinationMac(){
    return destinationMac;
  }
  public void setSourceMac(byte[] src){
    sourceMac = src;
  }

  public byte[] getSourceMac(){
    return sourceMac;
  }
  public void setEthertype(byte[] eth){
    ethertype = eth;
  }

  public byte[] getEthertype(){
    return ethertype;
  }

  //TO BE IMPLEMENTED
  public String resolveEthertype(){
    String etype = "";
    if(ethertype[0] == 8 && ethertype[1] ==0){
      etype = "IP";
    }
    else if(ethertype[0] == 8 && ethertype[1] ==6){
      etype = "ARP";
    }
    else{
      etype = "N/A"
    }
    return etype;
  }

  public String toString(){
    String src = new String(sourceMac, "UTF-8");
    String dest = new String(destinationMac, "UTF-8");
    String eth = new String(ethertype, "UTF-8");
    String output = "Ethernet:\n" +  "Destination address in bytes: "
      + dest + "\nSource Address in bytes: " + src + "\n Ethertype: " + resolveEthertype();
      return output;
  }
}
