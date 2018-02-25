import java.nio.ByteBuffer;
import java.io.File;
import java.io.FileInputStream;
import java.util.Scanner;
import java.io.FileInputStream;
import java.io.PrintWriter;


public class NetworkSecurityOne {

	public static void main(String[] args) {
    int count = 1000;
    String filename = "";
    boolean isFile = false;
		Scanner scan = null;
		FileInputStream fis;
		int filePointer = 0;
		boolean saveOutput = false;
		String outFileName = "";
		PrintWriter writer = null;

		SimplePacketDriver driver=new SimplePacketDriver();

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
				case "-o":
					idx++;
					outFileName = args[idx];
					saveOutput = true;
					try{
						writer = new PrintWriter(outFileName);
					} catch(Exception e){
						e.printStackTrace();
					}
					break;
    }
	}

    if(!isFile){
  		String[] adapters=driver.getAdapterNames();
      if (driver.openAdapter(adapters[0])) System.out.println("Adapter is open: "+adapters[0]);
    } else {
			try {
	      File file = new File(filename);
				scan = new Scanner(file);
				scan.useDelimiter("\\r\\n\\r\\n");
			} catch(Exception e){
				e.printStackTrace();
			}
		}

		int packetNum = 0;
    while((packetNum<count) && (!isFile || (scan.hasNext()))){
			byte [] packet = null;
			if(!isFile){
	      packet = driver.readPacket();
			} else {
				if(scan.hasNextLine()){
					String stgPacket = scan.next();
					packet = packetReader(stgPacket);
				}
			}
			ByteBuffer Packet = ByteBuffer.wrap(packet);
			//Print packet summary
			System.out.println("Packet: "+Packet+" with capacity: "+Packet.capacity());
			String stringPack = (driver.byteArrayToString(packet) + "\r\n").toString();
			System.out.println(stringPack);
			if(saveOutput){
				writer.println(outputStringify(packet) + "\r\n");
			}

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
			packetNum++;
		}
		writer.close();
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

	public static byte[] packetReader(String s){
		String st = s.replaceAll("\\s+","");
		System.out.println(st);
		return hexStringToByteArray(st);
	}

	public static byte[] hexStringToByteArray(String s) {
    int len = s.length();
    byte[] data = new byte[len / 2];
    for (int i = 0; i < len; i += 2) {
        data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                             + Character.digit(s.charAt(i+1), 16));
    }
    return data;
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
