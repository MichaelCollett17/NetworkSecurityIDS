import java.io.UnsupportedEncodingException;
import java.util.Arrays;

public class Ethernet {
	private byte[] packet;
	private byte[] destinationMac;
	private byte[] sourceMac;
	private byte[] ethertype;

	public Ethernet(byte[] packet_) {
		System.out.println(bytesToHex(packet_));
		this.packet = packet_;
		setDestinationMac(Arrays.copyOfRange(packet_, 0, 6));
		setSourceMac(Arrays.copyOfRange(packet_, 6, 12));
		setEthertype(Arrays.copyOfRange(packet_, 12, 14));
	}

	public void setDestinationMac(byte[] dest) {
		destinationMac = dest;
	}

	public byte[] getDestinationMac() {
		return destinationMac;
	}

	public void setSourceMac(byte[] src) {
		sourceMac = src;
	}

	public byte[] getSourceMac() {
		return sourceMac;
	}

	public void setEthertype(byte[] eth) {
		ethertype = eth;
	}

	public byte[] getEthertype() {
		return ethertype;
	}

	public String resolveEthertype() {
		String etype = "";
		if (ethertype[0] == 8 && ethertype[1] == 0) {
			etype = "ip";
		} else if (ethertype[0] == 8 && ethertype[1] == 6) {
			etype = "arp";
		} else {
			etype = "N/A";
		}
		return etype;
	}

	public String toString() {
		try {
			String src = bytesToHex(sourceMac);
			String dest = bytesToHex(destinationMac);
			String eth = bytesToHex(ethertype);
			String output = "Ethernet:\n" + "Destination address in bytes: " + dest + "\nSource Address in bytes: "
					+ src + "\nEthertype: " + resolveEthertype();
			return output;
		} catch (Exception e) {
			e.printStackTrace();
			return "";
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
}
