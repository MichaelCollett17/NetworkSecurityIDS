import java.net.InetAddress;

public class IPPacket extends Ethernet {
  private byte[] packet;
  private int version;// 4 bits
  private int IHL;// 4 bits
  private int TOS;//1 byte
  private int length;//2 bytes
  private int identification;//2 byte
  private boolean DFflag;//1 not frag, 0 frag ok
  private boolean MFflag;//1 more frags, 0 last frag
  private int TTL;//1 bytes
  private int protocol;//1 byte
  private int checksum;//2 bytes
  private InetAddress sourceAddress;//4 bytes
  private InetAddress destAddress;//4 bytes
  private byte[] options;


  public void setPacket(byte[] p){
    packet = p;
  }

  public byte[] getPacket(){
    return packet;
  }

  public void setOptions(byte[] o){
    options = o;
  }

  public byte[] getOptions(){
    return options;
  }

	/**
	* Returns value of version
	* @return
	*/
	public int getVersion() {
		return version;
	}

	/**
	* Sets new value of version
	* @param
	*/
	public void setVersion(int version) {
		this.version = version;
	}

	/**
	* Returns value of IHL
	* @return
	*/
	public int getIHL() {
		return IHL;
	}

	/**
	* Sets new value of IHL
	* @param
	*/
	public void setIHL(int IHL) {
		this.IHL = IHL;
	}

	/**
	* Returns value of TOS
	* @return
	*/
	public int getTOS() {
		return TOS;
	}

	/**
	* Sets new value of TOS
	* @param
	*/
	public void setTOS(int TOS) {
		this.TOS = TOS;
	}

	/**
	* Returns value of length
	* @return
	*/
	public int getLength() {
		return length;
	}

	/**
	* Sets new value of length
	* @param
	*/
	public void setLength(int length) {
		this.length = length;
	}

	/**
	* Returns value of identification
	* @return
	*/
	public int getIdentification() {
		return identification;
	}

	/**
	* Sets new value of identification
	* @param
	*/
	public void setIdentification(int identification) {
		this.identification = identification;
	}

	/**
	* Returns value of DFflag
	* @return
	*/
	public boolean isDFflag() {
		return DFflag;
	}

	/**
	* Sets new value of DFflag
	* @param
	*/
	public void setDFflag(boolean DFflag) {
		this.DFflag = DFflag;
	}

	/**
	* Returns value of MFflag
	* @return
	*/
	public boolean isMFflag() {
		return MFflag;
	}

	/**
	* Sets new value of MFflag
	* @param
	*/
	public void setMFflag(boolean MFflag) {
		this.MFflag = MFflag;
	}

	/**
	* Returns value of TTL
	* @return
	*/
	public int getTTL() {
		return TTL;
	}

	/**
	* Sets new value of TTL
	* @param
	*/
	public void setTTL(int TTL) {
		this.TTL = TTL;
	}

	/**
	* Returns value of protocol
	* @return
	*/
	public int getProtocol() {
		return protocol;
	}

	/**
	* Sets new value of protocol
	* @param
	*/
	public void setProtocol(int protocol) {
		this.protocol = protocol;
	}

	/**
	* Returns value of checksum
	* @return
	*/
	public int getChecksum() {
		return checksum;
	}

	/**
	* Sets new value of checksum
	* @param
	*/
	public void setChecksum(int checksum) {
		this.checksum = checksum;
	}

	/**
	* Returns value of sourceAddress
	* @return
	*/
	public InetAddress getSourceAddress() {
		return sourceAddress;
	}

	/**
	* Sets new value of sourceAddress
	* @param
	*/
	public void setSourceAddress(InetAddress sourceAddress) {
		this.sourceAddress = sourceAddress;
	}

	/**
	* Returns value of destAddress
	* @return
	*/
	public InetAddress getDestAddress() {
		return destAddress;
	}

	/**
	* Sets new value of destAddress
	* @param
	*/
	public void setDestAddress(InetAddress destAddress) {
		this.destAddress = destAddress;
	}
}
