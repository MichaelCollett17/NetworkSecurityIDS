public class ARP {
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
    
  }

	public int getArp_hardwareType() {
		return arp_hardwareType;
	}

	public void setArp_hardwareType(int arp_hardwareType) {
		this.arp_hardwareType = arp_hardwareType;
	}

	public int getArp_protocolType() {
		return arp_protocolType;
	}

	public void setArp_protocolType(int arp_protocolType) {
		this.arp_protocolType = arp_protocolType;
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
		this.arp_operation = arp_operation;
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
