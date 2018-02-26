import java.net.InetAddress;
import java.util.Arrays;
import java.nio.ByteBuffer;
import java.math.BigInteger;

public class ARP extends Ethernet {
  private byte[] arp_packet;
  private int arp_hardwareType;//2
  private int arp_protocolType;//2
  private int arp_hardwareAddressLength;//1
  private int arp_protocolAddressLength;//1
  private int arp_operation;//2
  private byte[] arp_sendHardAddress;//6
  private InetAddress arp_senderProtocolAddress;//4
  private byte[] arp_targetHardAddress;//6
  private InetAddress arp_targetProtocolAddress;//4

  public ARP(byte[] packet){
    super(packet);
    this.arp_packet = Arrays.copyOfRange(packet, 14, packet.length);
    setArp_hardwareType(new BigInteger(Arrays.copyOfRange(arp_packet, 0, 2)).intValue());
    setArp_protocolType(new BigInteger(Arrays.copyOfRange(arp_packet, 2, 4)).intValue());
    setArp_hardwareAddressLength(byteToUnsignedInt(arp_packet[4]));
    setArp_protocolAddressLength(byteToUnsignedInt(arp_packet[5]));

    try{
      int pointer = 8;
      setArp_operation(new BigInteger(Arrays.copyOfRange(arp_packet, 6, 8)).intValue());
      setArp_sendHardAddress(Arrays.copyOfRange(arp_packet, pointer, (pointer + arp_hardwareAddressLength)));
      pointer += arp_hardwareAddressLength;
      setArp_senderProtocolAddress(InetAddress.getByAddress(Arrays.copyOfRange(arp_packet, pointer, pointer + arp_protocolAddressLength)));
      pointer += arp_protocolAddressLength;
      setArp_targetHardAddress(Arrays.copyOfRange(arp_packet, pointer, (pointer + arp_hardwareAddressLength)));
      pointer += arp_hardwareAddressLength;
      setArp_targetProtocolAddress(InetAddress.getByAddress(Arrays.copyOfRange(arp_packet, pointer, pointer + arp_protocolAddressLength)));
    } catch(Exception e){
      e.printStackTrace();
      System.out.println("Error parsing addresses");
    }
  }

	public int getArp_hardwareType() {
		return arp_hardwareType;
	}

	public void setArp_hardwareType(int arp_hardwareType) {
    if(arp_hardwareType >= 0)
		  this.arp_hardwareType = arp_hardwareType;
    else
      this.arp_hardwareType = arp_hardwareType * -1;
	}

	public int getArp_protocolType() {
		return arp_protocolType;
	}

	public void setArp_protocolType(int arp_protocolType) {
    if(arp_protocolType >= 0)
		  this.arp_protocolType = arp_protocolType;
    else
      this.arp_protocolType = arp_protocolType * -1;
	}

	public int getArp_hardwareAddressLength() {
		return arp_hardwareAddressLength;
	}

	public void setArp_hardwareAddressLength(int arp_hardwareAddressLength) {
		this.arp_hardwareAddressLength = arp_hardwareAddressLength;
	}

	public int getArp_protocolAddressLength() {
		return arp_protocolAddressLength;
	}

	public void setArp_protocolAddressLength(int arp_protocolAddressLength) {
		this.arp_protocolAddressLength = arp_protocolAddressLength;
	}

	public int getArp_operation() {
		return arp_operation;
	}

	public void setArp_operation(int arp_operation) {
    if(arp_operation >= 0)
		  this.arp_operation = arp_operation;
    else
      this.arp_operation = arp_operation * -1;
	}

  public byte[] getArp_sendHardAddress(){
    return arp_sendHardAddress;
  }

  public void setArp_sendHardAddress(byte [] sendHardAddress){
    this.arp_sendHardAddress = sendHardAddress;
  }

	public InetAddress getArp_senderProtocolAddress() {
		return arp_senderProtocolAddress;
	}

	public void setArp_senderProtocolAddress(InetAddress arp_senderProtocolAddress) {
		this.arp_senderProtocolAddress = arp_senderProtocolAddress;
	}

  public byte[] getArp_targetHardAddress(){
    return arp_targetHardAddress;
  }

  public void setArp_targetHardAddress(byte[] targetHardAddress){
    this.arp_targetHardAddress = targetHardAddress;
  }

	public InetAddress getArp_targetProtocolAddress() {
		return arp_targetProtocolAddress;
	}

	public void setArp_targetProtocolAddress(InetAddress arp_targetProtocolAddress) {
		this.arp_targetProtocolAddress = arp_targetProtocolAddress;
	}

  public String toString(){
    return super.toString() + "\nHardware Type: " + this.getArp_hardwareType() + "\nProtocol Type: "
      + getArp_protocolType() + "\nHardware Address Length: " + getArp_hardwareAddressLength()
      + "\nProtocol Address Length: " + getArp_protocolAddressLength() + "\nOperation: "
      + getArp_operation() + "\nSender Harware Address: " + bytesToHex(getArp_sendHardAddress())
      + "\nSender Protocol Address: " + getArp_senderProtocolAddress().toString() +
      "\nTarget Hardware Address: " + bytesToHex(getArp_targetHardAddress()) + "\nTarget Protocol Address: "
      + getArp_targetProtocolAddress().toString();
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
