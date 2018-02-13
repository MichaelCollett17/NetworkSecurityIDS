import java.net.InetAddress;
import java.util.Arrays;
import java.nio.ByteBuffer;
import java.math.BigInteger;

public class IPPacket extends Ethernet {
  private byte[] ip_packet;
  private int ip_version;// 4 bits
  private int ip_IHL;// 4 bits
  private int ip_TOS;//1 byte
  private int ip_length;//2 bytes
  private int ip_identification;//2 byte
  private boolean ip_DFflag;//1 not frag, 0 frag ok
  private boolean ip_MFflag;//1 more frags, 0 last frag
  private int ip_TTL;//1 bytes
  private int ip_protocol;//1 byte
  private int ip_checksum;//2 bytes
  private InetAddress ip_sourceAddress;//4 bytes
  private InetAddress ip_destAddress;//4 bytes
  private byte[] ip_options;

  public IPPacket(byte[] packet) {
    super(packet);
    this.ip_packet = Arrays.copyOfRange(packet,14,packet.length);
    byte versionAndIHL = ip_packet[0];
    ip_version =  (int)(versionAndIHL >> 4);
    ip_IHL = (int)(versionAndIHL & 15);
    ip_TOS = (int) ip_packet[1];
    ip_length = (new BigInteger(Arrays.copyOfRange(ip_packet, 2, 4)).intValue());
    ip_identification = (new BigInteger(Arrays.copyOfRange(ip_packet, 4, 6)).intValue());
    if(((int)(ip_packet[6] >> 6)) == 1){
      ip_DFflag = true;
    }
    else{
      ip_DFflag = false;
    }
    System.out.println(bytesToHex(ip_packet));
    System.out.println(ip_version + "\n" + ip_IHL + "\n" + ip_TOS + "\n"
      + ip_length +"\n" + ip_identification + "\n" + ip_DFflag);
  }

  public void setip_packet(byte[] p){
    ip_packet = p;
  }

  public byte[] getip_packet(){
    return ip_packet;
  }

  public void setOptions(byte[] o){
    ip_options = o;
  }

  public byte[] getOptions(){
    return ip_options;
  }

	public int getIp_version() {
		return ip_version;
	}

	/**
	* Sets new value of ip_version
	* @param
	*/
	public void setIp_version(int ip_version) {
		this.ip_version = ip_version;
	}

	/**
	* Returns value of ip_IHL
	* @return
	*/
	public int getIp_IHL() {
		return ip_IHL;
	}

	/**
	* Sets new value of ip_IHL
	* @param
	*/
	public void setIp_IHL(int ip_IHL) {
		this.ip_IHL = ip_IHL;
	}

	/**
	* Returns value of ip_TOS
	* @return
	*/
	public int getIp_TOS() {
		return ip_TOS;
	}

	/**
	* Sets new value of ip_TOS
	* @param
	*/
	public void setIp_TOS(int ip_TOS) {
		this.ip_TOS = ip_TOS;
	}

	/**
	* Returns value of ip_length
	* @return
	*/
	public int getIp_length() {
		return ip_length;
	}

	/**
	* Sets new value of ip_length
	* @param
	*/
	public void setIp_length(int ip_length) {
		this.ip_length = ip_length;
	}

	/**
	* Returns value of ip_identification
	* @return
	*/
	public int getIp_identification() {
		return ip_identification;
	}

	/**
	* Sets new value of ip_identification
	* @param
	*/
	public void setIp_identification(int ip_identification) {
		this.ip_identification = ip_identification;
	}

	/**
	* Returns value of ip_DFflag
	* @return
	*/
	public boolean isIp_DFflag() {
		return ip_DFflag;
	}

	/**
	* Sets new value of ip_DFflag
	* @param
	*/
	public void setIp_DFflag(boolean ip_DFflag) {
		this.ip_DFflag = ip_DFflag;
	}

	/**
	* Returns value of ip_MFflag
	* @return
	*/
	public boolean isIp_MFflag() {
		return ip_MFflag;
	}

	/**
	* Sets new value of ip_MFflag
	* @param
	*/
	public void setIp_MFflag(boolean ip_MFflag) {
		this.ip_MFflag = ip_MFflag;
	}

	/**
	* Returns value of ip_TTL
	* @return
	*/
	public int getIp_TTL() {
		return ip_TTL;
	}

	/**
	* Sets new value of ip_TTL
	* @param
	*/
	public void setIp_TTL(int ip_TTL) {
		this.ip_TTL = ip_TTL;
	}

	/**
	* Returns value of ip_protocol
	* @return
	*/
	public int getIp_protocol() {
		return ip_protocol;
	}

	/**
	* Sets new value of ip_protocol
	* @param
	*/
	public void setIp_protocol(int ip_protocol) {
		this.ip_protocol = ip_protocol;
	}

	/**
	* Returns value of ip_checksum
	* @return
	*/
	public int getIp_checksum() {
		return ip_checksum;
	}

	/**
	* Sets new value of ip_checksum
	* @param
	*/
	public void setIp_checksum(int ip_checksum) {
		this.ip_checksum = ip_checksum;
	}

	/**
	* Returns value of ip_sourceAddress
	* @return
	*/
	public InetAddress getIp_sourceAddress() {
		return ip_sourceAddress;
	}

	/**
	* Sets new value of ip_sourceAddress
	* @param
	*/
	public void setIp_sourceAddress(InetAddress ip_sourceAddress) {
		this.ip_sourceAddress = ip_sourceAddress;
	}

	/**
	* Returns value of ip_destAddress
	* @return
	*/
	public InetAddress getIp_destAddress() {
		return ip_destAddress;
	}

	/**
	* Sets new value of ip_destAddress
	* @param
	*/
	public void setIp_destAddress(InetAddress ip_destAddress) {
		this.ip_destAddress = ip_destAddress;
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
