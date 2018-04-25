import java.util.Scanner;
import java.io.PrintWriter;
import java.io.File;

public class Signature{
  final static String any = "any";
  final static int colon = ':';
  private String rule = "";
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

  private boolean msgBool = false;
  private String msg = "";
  private boolean logBool = false;
  private String logFile = "logFile.txt";
  private boolean ttlBool = false;
  private int ttl = -1;
  private boolean tosBool = false;
  private int tos = -1;
  private boolean idBool = false;
  private int id = -1;
  private boolean fragOffBool = false;
  private int fragOffset = -1;
  private boolean ipOptionBool = false;
  private byte[] ipOptCode;
  private boolean fragBitBool = false;
  private boolean df = false;//D or !D dont fragment
  private boolean r = false;//R or !R reserved bit
  private boolean mf = false; //M or !M more frags
  private boolean notdf = false;//D or !D dont fragment
  private boolean notr = false;//R or !R reserved bit
  private boolean notmf = false; //M or !M more frags
  private boolean dSizeBool = false;
  private int dSize = -1;
  private boolean flagBool = false;
  private boolean tcp_ack = false;//A
  private boolean tcp_psh = false;//P
  private boolean tcp_rst = false;//R
  private boolean tcp_syn = false;//S
  private boolean tcp_fin = false;//F
  private boolean not_tcp_ack = false;//A
  private boolean not_tcp_psh = false;//P
  private boolean not_tcp_rst = false;//R
  private boolean not_tcp_syn = false;//S
  private boolean not_tcp_fin = false;//F
  private boolean seqBool = false;
  private int seq = -1;
  private boolean ackBool = false;
  private int ack = -1;
  private boolean itypeBool = false;
  private int itype = -1;
  private boolean icodeBool = false;
  private int icode = -1;
  private boolean contentBool = false;
  private String content;
  private boolean sameIP = false;
  private boolean sidBool = false;
  private int sid = -1;

  public Signature(String r){
    this.rule = r;
    setMainParams();
  }

  public boolean compare(IPPacket ip){
    boolean ruleMatch = false;
    ruleMatch = testIP(ip);
    if(ruleMatch)
      ruleMatch = testCommon(ip.getip_packet());
    System.out.println("IP: " + ruleMatch);
    return ruleMatch;
  }

  public boolean compare(ARP arp){
    boolean ruleMatch = false;
    ruleMatch = testCommon(arp.getArpPacket());
    System.out.println("ARP: " + ruleMatch);
    return ruleMatch;
  }

  public boolean compare(TCP tcp){
    boolean ruleMatch = false;
    ruleMatch = testTCP(tcp);
    if(ruleMatch)
      ruleMatch = testIP(tcp);
    if(ruleMatch)
      ruleMatch = testCommon(tcp.getTcpPacket());
    System.out.println("TCP: " + ruleMatch);
    return ruleMatch;
  }

  public boolean compare(UDP udp){
    boolean ruleMatch = false;
    ruleMatch = testIP(udp);
    if(ruleMatch)
      ruleMatch = testCommon(udp.getUDPPacket());
    System.out.println("UDP: " + ruleMatch);
    return ruleMatch;
  }

  public boolean compare(ICMP icmp){
    boolean ruleMatch = false;
    ruleMatch = testICMP(icmp);
    if(ruleMatch)
      ruleMatch = testIP(icmp);
    if(ruleMatch)
      ruleMatch = testCommon(icmp.getICMPPacket());
    System.out.println("ICMP: " + ruleMatch);
    return ruleMatch;
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
      ip2 = 0xffffffffL;//L is used for long
    }
    else {
      String[] parts = tempIP.split("/");
      ip1 = ipToLong(parts[0]);
      long endingFs = 0xffffffffL >>> Integer.parseInt(parts[1]);
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
        port2 = Integer.parseInt(tempPort.substring(indexOfColon + 1));
      }
    }

    //-> or <>
    String directionality = scanner.next();
    if(directionality.equals("->")){
      unidirectional = true;
    }
    else if(directionality.equals("<>")){
      unidirectional = false;
    }
    else{
      System.err.println("Misformatted signature");
    }

    String tempIP_ = scanner.next();
    if(tempIP_.equals(any)){
      ip3 = 0;
      ip4 = 0xffffffffL;//L is used for long
    }
    else {
      String[] parts = tempIP_.split("/");
      ip3 = ipToLong(parts[0]);
      long endingFs = 0xffffffffL >>> Integer.parseInt(parts[1]);
      ip4 = ip3 | endingFs;
    }

    String tempPort_ = scanner.next();
    if(tempPort_.equals(any)){
      port3 = 0;
      port4 = 65535;
    }
    else{
      int indexOfColon = tempPort_.indexOf(colon);//-1 not found, 0 = :port4, else port3:port4
      if(indexOfColon == -1) {
        port3 = Integer.parseInt(tempPort_);
        port4 = port3;
      }
      else if(indexOfColon == 0) {
        port3 = 0;
        port4 = Integer.parseInt(tempPort_.substring(1));
      }
      else{
        port3 = Integer.parseInt(tempPort_.substring(0, indexOfColon));
        port4 = Integer.parseInt(tempPort_.substring(indexOfColon + 1));
      }
    }
    if(scanner.hasNextLine()){
      options = scanner.nextLine();
      setOptions();
    }
    /*System.out.println("**********\nAlert:\t\t" + alert + "\nProtocol:\t"
      + protocol + "\nIP1:\t\t" + ip1 + "\nIP2:\t\t" + ip2 +
      "\nPort1:\t\t" + port1 + "\nPort2\t\t" + port2 +
      "\nUnidirectional:\t" + unidirectional + "\nIP3:\t\t" + ip3 + "\nIP4:\t\t"
       + ip4 + "\nPort3:\t\t" + port3 + "\nPort4\t\t" + port4 + "\nOptions:\t"
       + options + "\n**********\n");*/
  }

  private void setOptions(){
    //remove parentheses and space
    options = options.substring(2, options.length()-1);
    //split by semicolon and then colon
    String[] opts = options.split(";");
    for(int idx = 0; idx < opts.length; idx++){
      String[] option = opts[idx].split(":");
      String opt = option[0].replaceAll("\\s+","");
      switch(opt.toLowerCase()){
        case "msg":
          msgBool = true;
          msg = option[1].replace("\"", "");
          break;
        case "logto":
          logBool = true;
          logFile = option[1].replace("\"", "").replaceAll("\\s+","");
          break;
        case "ttl":
          ttlBool = true;
          ttl = Integer.parseInt(option[1].replaceAll("\\s+",""));
          break;
        case "tos":
          tosBool = true;
          tos = Integer.parseInt(option[1].replaceAll("\\s+",""));
          break;
        case "id":
          idBool = true;
          id = Integer.parseInt(option[1].replaceAll("\\s+",""));
          break;
        case "fragoffset":
          fragOffBool = true;
          fragOffset = Integer.parseInt(option[1].replaceAll("\\s+",""));
          break;
        case "ipoption":
          ipOptionBool = true;
          //Not sure what to do here
          break;
        case "fragbits":
          fragBitBool = true;
          if(option[1].toLowerCase().contains("!d"))
            notdf = true;
          else if(option[1].toLowerCase().contains("d"))
            df = true;
          if(option[1].toLowerCase().contains("!m"))
            notmf = true;
          else if(option[1].toLowerCase().contains("m"))
            mf = true;
          if(option[1].toLowerCase().contains("!r"))
            notr = true;
          else if(option[1].toLowerCase().contains("r"))
            r = true;
          break;
        case "dsize":
          dSizeBool = true;
          dSize = Integer.parseInt(option[1].replaceAll("\\s+",""));
          break;
        case "flags":
          flagBool = true;
          if(option[1].toLowerCase().contains("!a"))
            not_tcp_ack = true;
          else if(option[1].toLowerCase().contains("a"))
            tcp_ack = true;
          if(option[1].toLowerCase().contains("!p"))
            not_tcp_psh = true;
          else if(option[1].toLowerCase().contains("p"))
            tcp_psh = true;
          if(option[1].toLowerCase().contains("!r"))
            not_tcp_rst = true;
          else if(option[1].toLowerCase().contains("r"))
            tcp_rst = true;
          if(option[1].toLowerCase().contains("!s"))
            not_tcp_syn = true;
          else if(option[1].toLowerCase().contains("s"))
            tcp_syn = true;
          if(option[1].toLowerCase().contains("!f"))
            not_tcp_fin = true;
          else if(option[1].toLowerCase().contains("f"))
            tcp_fin = true;
          break;
        case "seq":
          seqBool = true;
          seq = Integer.parseInt(option[1].replaceAll("\\s+",""));
          break;
        case "ack":
          ackBool = true;
          ack = Integer.parseInt(option[1].replaceAll("\\s+",""));
          break;
        case "itype":
          itypeBool = true;
          itype = Integer.parseInt(option[1].replaceAll("\\s+",""));
          break;
        case "icode":
          icodeBool = true;
          icode = Integer.parseInt(option[1].replaceAll("\\s+",""));
          break;
        case "content":
          contentBool = true;
          content = option[1].replace("\"", "").replaceAll("\\s+","").replaceAll("\\|","");
          System.out.println(content);
          break;
        case "sameip":
          sameIP = true;
          break;
        case "sid":
          sidBool = true;
          sid = Integer.parseInt(option[1].replaceAll("\\s+",""));
          break;
      }
    }
  }
  //test for ttl, tos, id, fragoffset, fragbits, sameIP,
  private boolean testIP(IPPacket ip){
    if(ttlBool && (ip.getIp_TTL() != ttl))
      return false;
    if(tosBool && (ip.getIp_TOS() != tos))
      return false;
    if(idBool && (ip.getIp_identification() != id))
      return false;
    if(fragOffBool && (ip.getIp_fragmentOffset() != fragOffset))
      return false;
    if(fragBitBool){
      boolean ipdf = ip.isIp_DFflag();
      boolean ipmf = ip.isIp_MFflag();
      if(!((df && ipdf) | (notdf && !ipdf) | (mf && ipmf) | (notmf && !ipmf) | (r | notr))){
        return false;
      }
    }
    if(sameIP && !(ip.getIp_destAddress().getHostAddress().equals(ip.getIp_sourceAddress().getHostAddress())))
      return false;
    return true;
  }

  //test for flags, seq, and ack
  private boolean testTCP(TCP tcp){
    if(flagBool){
      if(!((tcp_ack && tcp.isTcp_ack())|(not_tcp_ack && !tcp.isTcp_ack())|
      (tcp_psh && tcp.isTcp_psh())|(not_tcp_psh && !tcp.isTcp_psh())|
      (tcp_rst && tcp.isTcp_rst())|(not_tcp_rst && !tcp.isTcp_rst())|
      (tcp_syn && tcp.isTcp_syn())|(not_tcp_syn && !tcp.isTcp_syn())|
      (tcp_fin && tcp.isTcp_fin())|(not_tcp_fin && !tcp.isTcp_fin()))){
        return false;
      }
    }
    if(seqBool && (seq != tcp.getTcp_sequenceNumber()))
      return false;
    if(ackBool && (ack != tcp.getTcp_ackNumber()))
      return false;
    return true;
  }

  //test for itype and icode
  private boolean testICMP(ICMP icmp){
    if(itypeBool && (itype != icmp.getIcmp_type()))
      return false;
    if(icodeBool && (icode != icmp.getIcmp_code()))
      return false;
    return true;
  }

  //dsize, content, logto, msg
  private boolean testCommon(byte[] packet){
    if(dSizeBool && (dSize != packet.length))
      return false;
    if(contentBool){
      SimplePacketDriver driver=new SimplePacketDriver();
      String packetString = driver.byteArrayToString(packet).replaceAll("//s+","").toLowerCase();
      //System.out.println(packetString);
      int indexOfContent = packetString.indexOf(content);
      if(indexOfContent != -1)
        return false;
    }
    if(alert){
      try{
        PrintWriter writer = new PrintWriter(logFile);
        writer.println(outputStringify(packet) + "\r\n");
        if(msgBool)
          writer.println(msg + "\r\n");
      } catch(Exception e){
        e.printStackTrace();
      }
    }
    return true;
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

  public static String bytesToHex(byte[] bytes) {
    char[] hexArray = "0123456789ABCDEF".toCharArray();
    char[] hexChars = new char[bytes.length * 2];
    for ( int j = 0; j < bytes.length; j++ ) {
        int v = bytes[j] & 0xFF;
        hexChars[j * 2] = hexArray[v >>> 4];
        hexChars[j * 2 + 1] = hexArray[v & 0x0F];
    }
    return new String(hexChars);
  }

  public static String outputStringify(byte [] b){
    String hex = bytesToHex(b);
    String output = "";
    for(int i = 0; i < hex.length(); i+=2){
      output += hex.substring(i,i+2) + " ";
      if((i% 32) == 30){
        output += "\r\n";
      }
    }
    return output;
  }
}
