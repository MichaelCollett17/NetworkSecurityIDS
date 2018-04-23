String tempIP = scanner.next();
    if(tempIP.equals(any)){
      ip1 = 0;
      ip2 = 0xffffffffL;//L is used for long
    }
    else {
      String[] parts = tempIP.split("/");
      ip1 = ipToLong(parts[0]);
      long endingFs = 0xffffffffL >>> Integer.parseInt(parts[1]);
      ip2 = ip1 | endingFs;
    }

    String tempPort = scanner.next();
    if(tempPort.equals(any)){
      port1 = 0;
      port2 = 65535;
    }
    else{
      int indexOfColon = tempPort.indexOf(colon);//-1 not found, 0 = :port2, else port1:port2
      if(indexOfColon == -1) {
        port1 = Integer.parseInt(tempPort);
        port2 = port1;
      }
      else if(indexOfColon == 0) {
        port1 = 0;
        port2 = Integer.parseInt(tempPort.substring(1));
      }
      else{
        port1 = Integer.parseInt(tempPort.substring(0, indexOfColon));
        port2 = Integer.parseInt(tempPort.substring(indexOfColon + 1));
      }
    }