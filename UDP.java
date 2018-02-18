import java.net.InetAddress;
import java.util.Arrays;
import java.nio.ByteBuffer;
import java.math.BigInteger;
import java.lang.Math;

public class UDP extends IPPacket{
  private byte[] udp_packet;
  private int udp_sourcePort;//2
  private int udp_destinationPort;//2
  private int udp_length;//2
  private byte[] udp_checksum;//2
  private byte[] udp_payload;

  public UDP(byte[] packet){
    super(packet);
    int ipLength = super.getIp_IHL();
    this.udp_packet = Arrays.copyOfRange(packet, (14 + (ipLength*4)), packet.length);
    setUdp_sourcePort(Math.abs(new BigInteger(Arrays.copyOfRange(udp_packet, 0, 2)).intValue()));
    setUdp_destinationPort(Math.abs(new BigInteger(Arrays.copyOfRange(udp_packet, 2, 4)).intValue()));
    setUdp_length(Math.abs(new BigInteger(Arrays.copyOfRange(udp_packet, 4, 6)).intValue()));
    setUdp_checksum(Arrays.copyOfRange(udp_packet,6,8));
    udp_payload = Arrays.copyOfRange(udp_packet,8,udp_packet.length);
  }

	public int getUdp_sourcePort() {
		return udp_sourcePort;
	}

	public void setUdp_sourcePort(int udp_sourcePort) {
		this.udp_sourcePort = udp_sourcePort;
	}

	public int getUdp_destinationPort() {
		return udp_destinationPort;
	}

	public void setUdp_destinationPort(int udp_destinationPort) {
		this.udp_destinationPort = udp_destinationPort;
	}

	public int getUdp_length() {
		return udp_length;
	}

	public void setUdp_length(int udp_length) {
		this.udp_length = udp_length;
	}

  public byte[] getUdp_checksum(){
    return udp_checksum;
  }

  public void setUdp_checksum(byte[] checksum){
    this.udp_checksum = checksum;
  }

  public byte[] getUdp_payload(){
    return udp_payload;
  }

  public String toString(){
    return "UDP:\nSource Port: " + getUdp_sourcePort() +
      "\nDestination Port: " + getUdp_destinationPort() + "\nLength: " +
      getUdp_length() + "\nChecksum: " +bytesToHex(getUdp_checksum()) +
      "\nPayload: " + bytesToHex(udp_payload);
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
}
