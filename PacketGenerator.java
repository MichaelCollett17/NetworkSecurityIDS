import java.io.File;
import java.util.Scanner;

public class PacketGenerator {
  public static void main(String[] args){
    String filename = args[1];//-f filename
    SimplePacketDriver driver=new SimplePacketDriver();
    //Get adapter names and print info
    String[] adapters=driver.getAdapterNames();
    System.out.println("Number of adapters: "+adapters.length);
    for (int i=0; i< adapters.length; i++) System.out.println("Device name in Java ="+adapters[i]);
    //Open first found adapter (usually first Ethernet card found)
    if (driver.openAdapter(adapters[0])) System.out.println("Adapter is open: "+adapters[0]);
    Scanner scan = null;
    try {
      File file = new File(filename);
      scan = new Scanner(file);
      scan.useDelimiter("\\r\\n\\r\\n");
    } catch(Exception e){
      e.printStackTrace();
    }
    byte[] packet = null;
    while(scan.hasNext()){
      if(scan.hasNextLine()){
        String stgPacket = scan.next();
        packet = packetReader(stgPacket);
        if(packet.length == 0)
          break;
      }
      //send packet
      if (!driver.sendPacket(packet)) {
        System.out.println("Error sending packet!!!" + bytesToHex(packet) +"\n" + packet.length);
      }
      else{
        System.out.println("Sent Successfully: " + bytesToHex(packet));
      }
    }
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
}
