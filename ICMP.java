import java.net.InetAddress;
import java.util.Arrays;
import java.nio.ByteBuffer;
import java.math.BigInteger;

public class ICMP extends IPPacket{
  private byte[] icmp_packet;
  private int icmp_type;//1 byte
  private int icmp_code;//1 byte
  private byte[] icmp_checksum;//2 bytes
  private byte[] icmp_payload;

  public ICMP(byte [] packet){
    super(packet);
    int ipLength = super.getIp_IHL();
    this.icmp_packet = Arrays.copyOfRange(packet, (14 + (ipLength*4)), packet.length);
    setIcmp_type(byteToUnsignedInt(icmp_packet[0]));
    setIcmp_code(byteToUnsignedInt(icmp_packet[1]));
    setIcmp_checksum(Arrays.copyOfRange(icmp_packet,2,4));
    setIcmp_payload(Arrays.copyOfRange(icmp_packet,4,icmp_packet.length));
  }

  public void setIcmp_payload(byte[] payload){
    this.icmp_payload = payload;
  }

  public byte[] getIcmp_payload(){
    return icmp_payload;
  }

	public int getIcmp_type() {
		return icmp_type;
	}

	public void setIcmp_type(int icmp_type) {
		this.icmp_type = icmp_type;
	}

	public int getIcmp_code() {
		return icmp_code;
	}

	public void setIcmp_code(int icmp_code) {
		this.icmp_code = icmp_code;
	}

  public byte[] getIcmp_checksum(){
    return icmp_checksum;
  }

  public void setIcmp_checksum(byte [] checksum){
    this.icmp_checksum = checksum;
  }

  public String toString(){
    return "ICMP:\nType: " + getIcmp_type() + "\nCode: " +
        getIcmp_code() + "\nChecksum: " + bytesToHex(getIcmp_checksum()) +
        "\nPayload: " + bytesToHex(getIcmp_payload());
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

  public static int byteToUnsignedInt(byte b) {
    return 0x00 << 24 | b & 0xff;
  }
}
