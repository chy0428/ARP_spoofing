package controller;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.scene.layout.AnchorPane;
import javafx.stage.Stage;

public class Main extends Application{
   
   public static Pcap pcap = null;
   public static PcapIf device = null;
   
   public static byte[] myIP = null;
   public static byte[] senderIP = null;
   public static byte[] targetIP = null;
   
   public static byte[] myMAC = null;
   public static byte[] senderMAC = null;
   public static byte[] targetMAC = null;
   
   private Stage primaryStage;
   private AnchorPane layout;
   
   @Override
   public void start(Stage primaryStage) { // program 창
      this.primaryStage = primaryStage;
      this.primaryStage.setTitle("JavaFx ARP Spoofing"); // program Subject
      this.primaryStage.setOnCloseRequest(e -> System.exit(0));
      setLayout();
   }
   
   public void setLayout() {
      try {
         FXMLLoader loader = new FXMLLoader();
         loader.setLocation(Main.class.getResource("../View/View.fxml")); // view.fxml 파일 가져오기 
         layout = (AnchorPane) loader.load();
         Scene scene = new Scene(layout); // stage 위에 scene 을 띄움
         primaryStage.setScene(scene);
         primaryStage.show();
      }catch (Exception e){ // 오류 발생시  
         e.printStackTrace();   //오류 출력 
      }
   }
   
   public Stage getPrimaryStage() {
      return primaryStage;
   }
   
   public static void main(String[] args) {
      launch(args);
   }

}