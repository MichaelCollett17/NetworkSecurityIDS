import java.util.Scanner;

public class Signature{
  final static String any = "any";
  final static int colon = ':';
  private String rule = "";
  private String logFile = "";
  private boolean alert = true;//if false -> pass
  private String protocol = "";
  private long ip1 = -1;//could be cidr or "any"
  private long ip2 = -1;
  private int port1 = -1;//inclusive begin port range
  private int port2 = -1;//inclusive end port range
  private boolean unidirectional = true;
  private long ip3 = -1;
  private long ip4 = -1;
  private int port3 = -1;
  private int port4 = -1;
  private String options = "";

  public Signature(String r){
    this.rule = r;
    setMainParams();
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
  private void setMainParams(){
    Scanner scanner = new Scanner(rule);
    if(scanner.next().equals("pass"))
      alert = false;//defaulted to true
    protocol = scanner.next();//NOTE: Don't forget to check case later

    String tempIP = scanner.next();
    if(tempIP.equals(any)){
      ip1 = 0;
      ip2 = 0xffffffff;
    }
    else {
      String[] parts = tempIP.split("/");
      ip1 = ipToLong(parts[0]);
      long endingFs = 0xffffffff >> Integer.parseInt(parts[1]);
      ip2 = ip1 | endingFs;
    }

    String tempPort = scanner.next();
    if(tempPort.equals(any)){
      port1 = 0;
      port2 = 65535;
    }
    else{
      int indexOfColon = tempPort.indexOf(colon);//-1 not found, 0 = :port2, else port1:port2
      if(indexOfColon == -1) {
        port1 = Integer.parseInt(tempPort);
        port2 = port1;
      }
      else if(indexOfColon == 0) {
        port1 = 0;
        port2 = Integer.parseInt(tempPort.substring(1));
      }
      else{
        port1 = Integer.parseInt(tempPort.substring(0, indexOfColon));
        port1 = Integer.parseInt(tempPort.substring(indexOfColon + 1));
      }
    }
    System.out.println("**********\nAlert:\t\t" + alert + "\nProtocol:\t"
      + protocol + "\nIP1:\t\t" + ip1 + "\nIP2:\t\t" + ip2 +
      "\nPort1:\t\t" + port1 + "\nPort2\t\t" + port2 + "\n**********\n");
  }

  public long ipToLong(String ipAddress) {
    String[] ipAddressInArray = ipAddress.split("\\.");
    long result = 0;
    for (int i = 0; i < ipAddressInArray.length; i++) {
      int power = 3 - i;
      int ip = Integer.parseInt(ipAddressInArray[i]);
      result += ip * Math.pow(256, power);
    }
    return result;
  }

}
