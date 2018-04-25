import java.net.InetAddress;
import java.util.Arrays;
import java.nio.ByteBuffer;
import java.math.BigInteger;
import java.lang.Math;

public class TCP extends IPPacket {
  private byte[] tcp_packet;
  private int tcp_sourcePort;//2
  private int tcp_destinationPort;//2
  private int tcp_sequenceNumber;//4
  private int tcp_ackNumber;//4
  private int tcp_dataOffset;//4 bits
  private int tcp_reserved;//6 bits
  private boolean tcp_urg;//packet[13] 1
  private boolean tcp_ack;//1
  private boolean tcp_psh;//1
  private boolean tcp_rst;//1
  private boolean tcp_syn;//1
  private boolean tcp_fin;//1
  private int tcp_window;//packet[14] 2
  private byte[] tcp_checksum;//2
  private int tcp_urgentPointer;//2
  private byte[] tcp_options;//?4
  private byte[] tcp_data;

  public TCP(byte[] packet){
    super(packet);
    int ipLength = super.getIp_IHL();
    this.tcp_packet = Arrays.copyOfRange(packet, (14 + (ipLength*4)), packet.length);
    setTcp_sourcePort(Math.abs(new BigInteger(Arrays.copyOfRange(tcp_packet, 0, 2)).intValue()));
    setTcp_destinationPort(Math.abs(new BigInteger(Arrays.copyOfRange(tcp_packet, 2, 4)).intValue()));
    setTcp_sequenceNumber(Math.abs(new BigInteger(Arrays.copyOfRange(tcp_packet, 4, 8)).intValue()));
    setTcp_ackNumber(Math.abs(new BigInteger(Arrays.copyOfRange(tcp_packet, 8, 12)).intValue()));
    setTcp_dataOffset((int)(((tcp_packet[12] >> 4) & 15)));
    int reservedFirstFour = (tcp_packet[12] & 15);
    int reservedLastTwo = (tcp_packet[13] >> 6);
    this.tcp_reserved = reservedFirstFour | reservedLastTwo;
    //last 6 bits of packet[13] byte
    setTcp_urg(((packet[13] & 32) >> 5) == 1);
    setTcp_ack(((packet[13] & 16) >> 4) == 1);
    setTcp_psh(((packet[13] & 8) >> 3) == 1);
    setTcp_rst(((packet[13] & 4) >> 2) == 1);
    setTcp_syn(((packet[13] & 2) >> 1) == 1);
    setTcp_fin((packet[13] & 1) == 1);
    setTcp_window(Math.abs(new BigInteger(Arrays.copyOfRange(tcp_packet, 14, 16)).intValue()));
    this.tcp_checksum = Arrays.copyOfRange(tcp_packet, 16, 18);
    setTcp_urgentPointer(Math.abs(new BigInteger(Arrays.copyOfRange(tcp_packet, 18, 20)).intValue()));
    int endHeader = 4 * getTcp_dataOffset();
    this.tcp_options = Arrays.copyOfRange(tcp_packet, 20, endHeader);
    this.tcp_data = Arrays.copyOfRange(tcp_packet, endHeader, tcp_packet.length);
  }

  public byte[] getTcpPacket(){
    return tcp_packet;
  }

	public int getTcp_sourcePort() {
		return tcp_sourcePort;
	}

	public void setTcp_sourcePort(int tcp_sourcePort) {
		this.tcp_sourcePort = tcp_sourcePort;
	}

	public int getTcp_destinationPort() {
		return tcp_destinationPort;
	}

	public void setTcp_destinationPort(int tcp_destinationPort) {
		this.tcp_destinationPort = tcp_destinationPort;
	}

	public int getTcp_sequenceNumber() {
		return tcp_sequenceNumber;
	}

	public void setTcp_sequenceNumber(int tcp_sequenceNumber) {
		this.tcp_sequenceNumber = tcp_sequenceNumber;
	}

	public int getTcp_ackNumber() {
		return tcp_ackNumber;
	}

	public void setTcp_ackNumber(int tcp_ackNumber) {
		this.tcp_ackNumber = tcp_ackNumber;
	}

	public int getTcp_dataOffset() {
		return tcp_dataOffset;
	}

	public void setTcp_dataOffset(int tcp_dataOffset) {
		this.tcp_dataOffset = tcp_dataOffset;
	}

	public boolean isTcp_urg() {
		return tcp_urg;
	}

	public void setTcp_urg(boolean tcp_urg) {
		this.tcp_urg = tcp_urg;
	}

	public boolean isTcp_ack() {
		return tcp_ack;
	}

	public void setTcp_ack(boolean tcp_ack) {
		this.tcp_ack = tcp_ack;
	}

	public boolean isTcp_psh() {
		return tcp_psh;
	}

	public void setTcp_psh(boolean tcp_psh) {
		this.tcp_psh = tcp_psh;
	}

	public boolean isTcp_rst() {
		return tcp_rst;
	}

	public void setTcp_rst(boolean tcp_rst) {
		this.tcp_rst = tcp_rst;
	}

	public boolean isTcp_syn() {
		return tcp_syn;
	}

	public void setTcp_syn(boolean tcp_syn) {
		this.tcp_syn = tcp_syn;
	}

	public boolean isTcp_fin() {
		return tcp_fin;
	}

	public void setTcp_fin(boolean tcp_fin) {
		this.tcp_fin = tcp_fin;
	}

	public int getTcp_window() {
		return tcp_window;
	}

	public void setTcp_window(int tcp_window) {
		this.tcp_window = tcp_window;
	}

	public int getTcp_urgentPointer() {
		return tcp_urgentPointer;
	}

	public void setTcp_urgentPointer(int tcp_urgentPointer) {
		this.tcp_urgentPointer = tcp_urgentPointer;
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
  public String toString(){
    return super.toString() + "\nTCP\nSource Port: " + getTcp_sourcePort() +
    "\nDestination Port: " + getTcp_destinationPort() + "\nSequence Number: " +
    getTcp_sequenceNumber() + "\nAck Number: " + getTcp_ackNumber() + "\nData Offset: "
    + getTcp_dataOffset() + "\nReserved Bits (last 6 of byte): "
    + String.format("%8s", Integer.toBinaryString(tcp_reserved & 0xFF)).replace(' ', '0')
    + "\nUrg: " + isTcp_urg() + "\nAck: " + isTcp_ack()+ "\nPsh: " + isTcp_psh()
    + "\nRst: " + isTcp_rst()+ "\nSyn: " + isTcp_syn() + "\nFin: " + isTcp_fin()
    +"\nWindow Size: " + getTcp_window() + "\nChecksum: " + bytesToHex(tcp_checksum) +
    "\nUrgent Pointer: " + getTcp_urgentPointer() + "\nOptions: " + bytesToHex(tcp_options)
    + "\nData: " + bytesToHex(tcp_data);
  }
}
