import java.nio.ByteBuffer;

public class Sniffer {

	public static void main(String[] args) {
        SimplePacketDriver driver=new SimplePacketDriver();
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

				//Figure Ethertype
				if(packet[12] == 8 && packet[13] ==0){
					System.out.println("IP");
				}
				else if(packet[12] == 8 && packet[13] ==6){
					System.out.println("ARP");
				}
				else{
					System.our.println("EtherType not implemented yet");
				}
}
}
