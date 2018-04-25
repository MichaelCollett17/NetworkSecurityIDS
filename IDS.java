import java.nio.ByteBuffer;
import java.io.File;
import java.io.FileInputStream;
import java.util.Scanner;
import java.io.FileInputStream;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.util.ArrayList;

public class IDS {
	private static  int count = 1000;
	private static String filename = "";
	private static boolean isFile = false;
	private static Scanner scan = null;
	private static FileInputStream fis;
	private static int filePointer = 0;
	private static boolean saveOutput = false;
	private static String outFileName = "";
	private static PrintWriter writer = null;
	private static boolean filterType = false;
	private static String filterVal = "";
	private static boolean filterSrc = false;
	private static InetAddress src = null;
	private static boolean filterDst = false;
	private static InetAddress dst = null;
	private static boolean sord = false;
	private static boolean filtSPort = false;
	private static int sPortMin = -1;
	private static int sPortMax = -1;
	private static boolean filtDPort = false;
	private static int dPortMin = -1;
	private static int dPortMax = -1;
	private static long timeout = 20000;
	private static String signatureFile = "signatures.txt";
	private static String logFile = "log.txt";
	private static ArrayList<Signature> signatures = new ArrayList<Signature>();

	public static void main(String[] args) {


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
				case "-t":
					idx++;
					filterVal = args[idx];
					filterType = true;
					break;
				case "-src":
					idx++;
					filterSrc = true;
					try{
						src = InetAddress.getByName(args[idx]);
					} catch(Exception e){
						e.printStackTrace();
					}
					break;
				case "-dst":
					idx++;
					filterDst = true;
					try{
						dst = InetAddress.getByName(args[idx]);
					} catch(Exception e){
						e.printStackTrace();
					}
					break;
				case "-sord":
					sord = true;
					//source
					idx++;
					filterSrc = true;
					try{
						src = InetAddress.getByName(args[idx]);
					} catch(Exception e){
						e.printStackTrace();
					}
					//destination
					idx++;
					filterDst = true;
					try{
						dst = InetAddress.getByName(args[idx]);
					} catch(Exception e){
						e.printStackTrace();
					}
					break;
				case "-sandd":
					//source
					idx++;
					filterSrc = true;
					try{
						src = InetAddress.getByName(args[idx]);
					} catch(Exception e){
						e.printStackTrace();
					}
					//destination
					idx++;
					filterDst = true;
					try{
						dst = InetAddress.getByName(args[idx]);
					} catch(Exception e){
						e.printStackTrace();
					}
					break;
				case "-sport":
					filtSPort = true;
					idx++;
					sPortMin = Integer.parseInt(args[idx]);
					idx++;
					sPortMax = Integer.parseInt(args[idx]);
					break;
				case "-dport":
					filtDPort = true;
					idx++;
					dPortMin = Integer.parseInt(args[idx]);
					idx++;
					dPortMax = Integer.parseInt(args[idx]);
					break;
				case "-timeout":
					idx++;
					timeout = Integer.parseInt(args[idx]);
					break;
				case "-f":
					idx++;
					signatureFile = args[idx];
					break;
    }
	}

		//build signature List
		try{
		File sigFile = new File(signatureFile);
		Scanner sigScanner = new Scanner(sigFile);
		while(sigScanner.hasNextLine()){
			Signature sig = new Signature(sigScanner.nextLine());
			signatures.add(sig);
		}
	} catch(Exception e){
		e.printStackTrace();
	}

    if(!isFile){
  		String[] adapters=driver.getAdapterNames();
			for (int i=0; i< adapters.length; i++) System.out.println("Device name in Java ="+adapters[i]);
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

		Reassembler reassembler = new Reassembler(timeout);
		int packetNum = 0;
    while((packetNum<count) && (!isFile || (scan.hasNext()))){
			byte [] packet = null;
			if(!isFile){
	      packet = driver.readPacket();
			} else {
				if(scan.hasNext()){
					String stgPacket = scan.next();
					packet = packetReader(stgPacket);
				}
			}
			packetNum++;
			AssembledTriple at = reassembler.processFragment(packet);
			if(at == null){
			}
			else if(at.getSID() == -10){
				System.out.println("Packet Dropped Due to False Checksum");
			}
			else if((at.getSID() == 0)|(at.getSID() == 1)|(at.getSID() == 2)){
				analyze(at.getAssembledPacket(), at);
			}
			else if(at.getSID() == 3){
				System.out.println("Warning: Oversized Packet");
			}
			else if(at.getSID() == 4){
				//timedout
			}
			AssembledTriple at_ = reassembler.checkTimeouts();
			if(at_ == null){
			}
			else if(at_.getSID() == -10){
				System.out.println("Packet Dropped Due to False Checksum");
			}
			else if((at_.getSID() == 0)|(at.getSID() == 1)|(at.getSID() == 2)){
				analyze(at_.getAssembledPacket(), at);
			}
			else if(at_.getSID() == 3){
				System.out.println("Warning: Oversized Packet");
			}
			else if(at_.getSID() == 4){
				System.out.println("Fragments Timed Out");
			}
		}
		if(saveOutput)
			writer.close();
	}

	public static void analyze(byte[] packet, AssembledTriple at){
		SimplePacketDriver driver = new SimplePacketDriver();
		Ethernet ethernet = new Ethernet(packet);
		if(filterType && filterVal.equals("eth")){
			if(saveOutput){
				writer.println(outputStringify(packet) + "\r\n");
			}
			System.out.println(ethernet.toString());
		}
		String ethertype = ethernet.resolveEthertype();
		if(ethertype.equals("ip")){
			IPPacket ip = new IPPacket(packet);
			String iptype = ip.resolveIPProtocol();
			if(!sord && ((filterSrc && (!src.toString().equals(ip.getIp_sourceAddress().toString()))) ||
						(filterDst && (!dst.toString().equals(ip.getIp_destAddress().toString()))))){
				return;
			}	else if(sord){
				if(((!src.toString().equals(ip.getIp_sourceAddress().toString()))) &&
							(!dst.toString().equals(ip.getIp_destAddress().toString()))){
					return;
				}
			}
			if(filterType && filterVal.equals("ip")){
				boolean sigMatch = IPSignatureChecker(at);
				if(!sigMatch){
					if(saveOutput){
						writer.println(outputStringify(packet) + "\r\n");
					}
					System.out.println(ip.toString());
				}
			}
			if(iptype.equals("icmp")){
				ICMP icmp = new ICMP(packet);
				if((!filterType) || filterVal.equals("icmp")){
					boolean sigMatch = ICMPSignatureChecker(at);
					if(!sigMatch){
						if(saveOutput){
							writer.println(outputStringify(packet) + "\r\n");
						}
						System.out.println(icmp.toString());
				}
				}
			}
			else if(iptype.equals("udp")){
				UDP udp = new UDP(packet);
				if((filtSPort) && !((udp.getUdp_sourcePort() <= sPortMax) && (udp.getUdp_sourcePort() >= sPortMin))){
					return;
				}
				if((filtDPort) && !((udp.getUdp_destinationPort() <= dPortMax) && (udp.getUdp_destinationPort() >= dPortMin))){
					return;
				}
				if((!filterType) || filterVal.equals("udp")){
					boolean sigMatch = UDPSignatureChecker(at);
					if(!sigMatch){
						System.out.println(udp.toString());
						if(saveOutput){
							writer.println(outputStringify(packet) + "\r\n");
						}
					}
				}

			}
			else if(iptype.equals("tcp")){
				TCP tcp = new TCP(packet);
				if((filtSPort) && !((tcp.getTcp_sourcePort() <= sPortMax) && (tcp.getTcp_sourcePort() >= sPortMin))){
					return;
				}
				if((filtDPort) && !((tcp.getTcp_destinationPort() <= dPortMax) && (tcp.getTcp_destinationPort() >= dPortMin))){
					return;
				}
				if((!filterType) || filterVal.equals("tcp")){
					boolean sigMatch = TCPSignatureChecker(at);
					if(!sigMatch){
						System.out.println(tcp.toString());
						if(saveOutput){
							writer.println(outputStringify(packet) + "\r\n");
						}
					}
				}
			}
		} else if(ethertype.equals("arp")){
			ARP a = new ARP(packet);
			if(!sord && ((filterSrc && (!src.toString().equals(a.getArp_senderProtocolAddress().toString())))||
			((filterDst && (!dst.toString().equals(a.getArp_targetProtocolAddress().toString())))))){
				return;
			}
			else if(sord){
				if((!src.toString().equals(a.getArp_senderProtocolAddress().toString())) &&
				(!dst.toString().equals(a.getArp_targetProtocolAddress().toString()))){
					return;
				}
			}
			if((!filterType) || filterVal.equals("arp")){
				boolean sigMatch = ARPSignatureChecker(at);
				if(!sigMatch){
					System.out.println(a.toString());
					if(saveOutput){
						writer.println(outputStringify(packet) + "\r\n");
					}
				}
			}
		} else{
			System.out.println("Unimplemented type!\n");
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

	public static boolean IPSignatureChecker(AssembledTriple at){
		boolean sigMatch = false;
		//check each fragment and the assembled packet
		IPPacket packet = new IPPacket(at.getAssembledPacket());
		ArrayList<byte[]> fragments = at.getFragments();
		for(int i = 0; i < fragments.size(); i++){
			IPPacket frag = new IPPacket(fragments.get(i));
			for(int idx = 0; idx < signatures.size(); idx++){
				sigMatch = signatures.get(idx).compare(frag);
			}
		}
		for(int index = 0; index < signatures.size(); index++){
			sigMatch = signatures.get(index).compare(packet);
		}

		return sigMatch;
	}

	public static boolean ARPSignatureChecker(AssembledTriple at){
		boolean sigMatch = false;
		ARP packet = new ARP(at.getAssembledPacket());
		for(int index = 0; index < signatures.size(); index++){
			sigMatch = signatures.get(index).compare(packet);
		}

		return sigMatch;
	}

	public static boolean TCPSignatureChecker(AssembledTriple at){
		boolean sigMatch = false;
		//check each fragment and the assembled packet
		TCP packet = new TCP(at.getAssembledPacket());
		ArrayList<byte[]> fragments = at.getFragments();
		for(int i = 0; i < fragments.size(); i++){
			TCP frag = new TCP(fragments.get(i));
			for(int idx = 0; idx < signatures.size(); idx++){
				sigMatch = signatures.get(idx).compare(frag);
			}
		}
		for(int index = 0; index < signatures.size(); index++){
			sigMatch = signatures.get(index).compare(packet);
		}

		return sigMatch;
	}

	public static boolean UDPSignatureChecker(AssembledTriple at){
		boolean sigMatch = false;
		//check each fragment and the assembled packet
		UDP packet = new UDP(at.getAssembledPacket());
		ArrayList<byte[]> fragments = at.getFragments();
		for(int i = 0; i < fragments.size(); i++){
			UDP frag = new UDP(fragments.get(i));
			for(int idx = 0; idx < signatures.size(); idx++){
				sigMatch = signatures.get(idx).compare(frag);
			}
		}
		for(int index = 0; index < signatures.size(); index++){
			sigMatch = signatures.get(index).compare(packet);
		}

		return sigMatch;
	}

	public static boolean ICMPSignatureChecker(AssembledTriple at){
		boolean sigMatch = false;
		//check each fragment and the assembled packet
		ICMP packet = new ICMP(at.getAssembledPacket());
		ArrayList<byte[]> fragments = at.getFragments();
		for(int i = 0; i < fragments.size(); i++){
			ICMP frag = new ICMP(fragments.get(i));
			for(int idx = 0; idx < signatures.size(); idx++){
				sigMatch = signatures.get(idx).compare(frag);
			}
		}
		for(int index = 0; index < signatures.size(); index++){
			sigMatch = signatures.get(index).compare(packet);
		}

		return sigMatch;
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
