package broadcastchatserver;

import java.io.IOException;
import java.net.ServerSocket;

public class BroadcastChatServer {
    /**
     * Versione del server
     */
    private static final String version = "BroadcastChatServer V0.2";
    /**
     * Porta utilizzata per la comunicazione
     */
    private static final int PORT = 8888;
    /**
     * SocketServer
     */
    private static ServerSocket s;
    public static void main(String[] args) {
        System.out.println(version);
        try {
            // Creo il socketServer
            s = new ServerSocket(PORT);
            System.out.println("Server in ascolto sulla porta " + PORT);
            // Accetto tutte le possibili connessioni e per ogniuna creo un nuovo server che la gestisce
            while(true)
                new ClientManager(s.accept()).start();
        } catch (IOException ex) {
            System.out.println("ERRORE DI RETE!!! SERVER ARRESTATO");
            System.exit(0);
        }
    }    
}