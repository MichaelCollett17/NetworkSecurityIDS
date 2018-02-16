import java.nio.ByteBuffer;

public class Sniffer {

	public static void main(String[] args) {
        SimplePacketDriver driver=new SimplePacketDriver();
				boolean arp = false;
				while(!arp){
					String[] adapters=driver.getAdapterNames();
		//Open first found adapter (usually first Ethernet card found)
		//Recieving ethernet packets becuase it's the lowest level of software
	        if (driver.openAdapter(adapters[0])) System.out.println("Adapter is open: "+adapters[0]);
		//Read a packet (blocking operation)
	        byte [] packet=driver.readPacket();
	        //Wrap it into a ByteBuffer
	        ByteBuffer Packet=ByteBuffer.wrap(packet);
	        //Print packet summary
	        System.out.println("Packet: "+Packet+" with capacity: "+Packet.capacity());
	        System.out.println(driver.byteArrayToString(packet));

					Ethernet ethernet = new Ethernet(packet);
					System.out.println(ethernet.toString());
					String ethertype = ethernet.resolveEthertype();
					if(ethertype == "IP"){
						IPPacket ip = new IPPacket(packet);
						System.out.println(ip.toString());
					} else if(ethertype == "ARP"){
						ARP a = new ARP(packet);
						arp = true;
					} else{
						System.out.println("Unimplemented type");
					}
				}
			}
}
