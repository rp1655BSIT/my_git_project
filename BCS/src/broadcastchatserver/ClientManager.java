package broadcastchatserver;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.Cipher;

public class ClientManager extends Thread{
    /**
     * Flag utilizzate per la comunicazione con i vari client
     */
    public static final String USERNAME_NOT_AVAILABLE = "INVALIDUSERNAME", USERNAME_AVAILABLE = "OK", NEW_MESSAGE_BD = "BD",
            WRITING = "W:", STOP_WRITING = "!W:", NEW_USER = "IN:", EXIT_USER = "OUT:", CLOSE = "Bye", NEW_MESSAGE_PC = "PC";
    /**
     * 
     * Mappa statica, quindi condivisa tra tutte le istanze contenente tutti i canali
     * di scrittura verso i client connessi
     */
    private static Map<String, PrintWriter> clients = new HashMap();
    /**
        Mappa che contiene tutte le chiavi pubbliche dei vari client
    **/
    private static Map<String, PublicKey> clientsPublicKey = new HashMap();
    /**
     * Canale di ricezione dal client
     */
    private BufferedReader fromClient;
    /**
     * Canale di scrittura verso il client
     */
    private PrintWriter toClient;
    /**
     * Nomeutente del client
     */
    private String username;
    /**
        Chiave pubblica del server
    **/
    private volatile static RSAPublicKeySpec serverPublicKey;
    /**
        Chiave privata del server
    **/
    private volatile static PrivateKey serverPrivateKey;
    /**
        Invia in boadcast il messaggio passato come argomento
        @param message Messaggio da mandare in broadcast
    **/
    private void sendBroadcast(String message){
        for(Map.Entry<String, PrintWriter> c : clients.entrySet())
            if(!username.equals(c.getKey()))
                c.getValue().println(message);
    }

    public ClientManager(Socket client){
        if(serverPublicKey == null) // Se la chiavi del server non sono ancora state generate...
            try {
                generateServerKey(); // Le genero
            }catch(Exception ex) {
                System.err.println("Impossibile generare le chiavi del server");
                System.exit(-1);
            }
        try {
            fromClient = new BufferedReader(new InputStreamReader(client.getInputStream()));
            toClient = new PrintWriter(client.getOutputStream(), true);
            // Ricevo il nome dell'utente
            this.username = fromClient.readLine();
            // Nel caso in cui il nome non sia disponibile
            if(clients.containsKey(username)) {
                // Lo comunico al server
                toClient.println(USERNAME_NOT_AVAILABLE);
                client.close();
                return ;
            }
            // Avviso il client che il suo nome è disponibile
            toClient.println(USERNAME_AVAILABLE);
            // Aggiungo il client alla mappa
            clients.put(username, toClient);
            System.out.println(username + " ha efettuato l'accesso.");
        } catch (IOException ex) {
            System.out.println("Errore durante la comunicazione con un nuovo client.");
        }
    }
    /**
     * Invia la lista di tutti gli utenti al client gestito da questa istanza
     */
    private void sendUserList(){
        // Itero tutti i client
        for(Map.Entry<String, PrintWriter> c : clients.entrySet())
            if(!username.equals(c.getKey()))
                toClient.println(NEW_USER + c.getKey());
    }
    /**
        Genera le chiavi del server che verranno utilizzate per i messaggi privati
    **/
    public void generateServerKey() throws Exception{
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.genKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        serverPrivateKey = keyPair.getPrivate();
        KeyFactory fact = KeyFactory.getInstance("RSA");        
        ClientManager.serverPublicKey = fact.getKeySpec(publicKey, RSAPublicKeySpec.class);
    }
    
    @Override
    public void run(){
        // Invio la chiave pubblica del server al client
        toClient.println(serverPublicKey.getModulus());
        toClient.println(serverPublicKey.getPublicExponent());
        // Mi assicuro che tutti i dati siano stati inviati
        toClient.flush();
        
        // Ricevo la chiave pubblica del client
        PublicKey clientPublicKey;
        try {
            RSAPublicKeySpec clientPublicKeySpec = new RSAPublicKeySpec(new BigInteger(fromClient.readLine()), new BigInteger(fromClient.readLine()));
            KeyFactory fact = KeyFactory.getInstance("RSA");
            clientPublicKey = fact.generatePublic(clientPublicKeySpec);
            clientsPublicKey.put(username, clientPublicKey); // e la aggiungo alla mappa
        } catch(Exception ex) {
            System.err.println("Errore durante la lettura delle chiavi di un client");
        }        
        sendBroadcast(NEW_USER + username); // Dico a tutti i client che un nuovo utente si è connesso
        sendUserList(); // Invio la lista degli utenti al client appena connesso
        while(true){
            String in = "";
            try {
                in = fromClient.readLine();
            } catch (IOException ex) {
                System.out.println("Errore di connessione con il client " + username);
                break;
            }
            if(in.startsWith(NEW_MESSAGE_BD)) // Messaggio broadcast
                this.sendBroadcast(NEW_MESSAGE_BD + username + ":" + in.substring(NEW_MESSAGE_BD.length()));
            else if(in.startsWith(NEW_MESSAGE_PC)){ // Private message
                // Decripto il messaggio ricevuto con la chiave privata del Server
                String decripted = decryptPrivateMessage(in.substring(NEW_MESSAGE_PC.length()));
                // Invio il messaggio al client
                sendPrivate(decripted);
            } else if(in.startsWith(WRITING)) // Start typing
                this.sendBroadcast(WRITING + username);
            else if(in.startsWith(STOP_WRITING)) // Stop typing
                this.sendBroadcast(STOP_WRITING + username);
            else if(in.equals(CLOSE)) // Disconnection
                break;
        }        
       clients.remove(username);
       sendBroadcast(EXIT_USER + username);
       System.out.println(username + " si è disconnesso...");
    }
    /**
     * Decripta un messaggio privato con la chiave privata del server
     * @param str Stringa da decriptare
     * @return Stringa decriptata
     */
    private String decryptPrivateMessage(String str) {
        // Decripto un messaggio con la MIA chiave privata
        try {
            // Creo ed inizializzo il cipher
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, serverPrivateKey);
            String decripted = new String(cipher.doFinal(bytify(str)), "UTF8");
            return decripted;
        } catch(Exception ex) {
            System.out.println(ex.toString() + ex.getLocalizedMessage() + ex.getMessage() + ex.getCause());
        }
        return null;
    }
    /**
     * Cripto una stringa da inviare ad un clòient con la chiave pubblica del
     * destinatario
     * @param str Stringa da criptare
     * @param toName Destinatario
     * @return Stringa criptata
     */
    private String cryptPrivateMessage(String str, String toName) {
        // Cripto con la chiave pubblica del ricevitore
        try {
            // Creo ed inizializzo il cipher
            Cipher cipher = Cipher.getInstance("RSA");
            // Cripto la stringa
            cipher.init(Cipher.ENCRYPT_MODE, clientsPublicKey.get(toName));
            // E trasformo  il vettore di byte criptato in una stringa
            return stringify(cipher.doFinal(str.getBytes("UTF8")));
        }catch(Exception ex) {
            System.out.println("" + ex);
        }
        return null;
    }
    /**
     * invia un messaggio privato
     * @param str 
     */
    private void sendPrivate(String str){
        String name = str.substring(0, str.indexOf(":")); // Ricavo il destinatario dalla stringa
        // Invio al client il nuovo messaggio criptato con la chiave pubblica del client destinatario
        clients.get(name).println(NEW_MESSAGE_PC + cryptPrivateMessage(str, name));
    }
    
    /**
     * Trasffroma un vettore di byte in una stringa utilizzando il Base64
     * @param bytes Vettore di byte
     * @return Stringa
     */
    public static String stringify(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }
    /**
     * Ritrasforma una stringa in un vettore di byte
     * @param str Stringa
     * @return vettore
     */
    public static byte[] bytify(String str) {
        return Base64.getDecoder().decode(str);
    }
}
