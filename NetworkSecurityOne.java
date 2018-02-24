import java.nio.ByteBuffer;
import java.io.File;
import java.io.FileInputStream;

public class NetworkSecurityOne {

	public static void main(String[] args) {
    int count = 1000;
    String filename = "";
    boolean isFile = false;

    for(int idx = 0; idx < args.length; idx++){
      String arg = args[idx];
      switch(arg.toLowerCase()){
        case "-c":
          idx++;
          count = Integer.parseInt(args[idx]);
          break;
        case "-r":
          idx++;
          filename = args[idx];
          isFile = true;
          break;
      }
    }

    //if(!isFile){
      SimplePacketDriver driver=new SimplePacketDriver();
  		String[] adapters=driver.getAdapterNames();
      if (driver.openAdapter(adapters[0])) System.out.println("Adapter is open: "+adapters[0]);
    //} else {
    //  File file = new File(filename);
    //}

    for(int packetNum = 0; packetNum<count; packetNum++){
      byte [] packet=driver.readPacket();
      ByteBuffer Packet=ByteBuffer.wrap(packet);
      //Print packet summary
      System.out.println("Packet: "+Packet+" with capacity: "+Packet.capacity());
      System.out.println(driver.byteArrayToString(packet));

			Ethernet ethernet = new Ethernet(packet);
			System.out.println(ethernet.toString());
			String ethertype = ethernet.resolveEthertype();
			if(ethertype == "ip"){
				IPPacket ip = new IPPacket(packet);
				System.out.println(ip.toString());
				String iptype = ip.resolveIPProtocol();
				if(iptype == "icmp"){
					ICMP icmp = new ICMP(packet);
					System.out.println(icmp.toString());
				}
				else if(iptype == "udp"){
					UDP udp = new UDP(packet);
					System.out.println(udp.toString());
				}
				else if(iptype == "tcp"){
					TCP tcp = new TCP(packet);
				}
			} else if(ethertype == "arp"){
				ARP a = new ARP(packet);
			} else{
				System.out.println("Unimplemented type");
			}
		}
	}
}
