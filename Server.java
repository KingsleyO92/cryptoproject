//Written by Kingsley Obi
//March 2022

import java.net.*;
import java.io.*;
import java.util.*;
import java.security.*;
import java.math.*;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;


//Arguments: Name Port


public class Server {


	//Helper Class for making messages moe functional
	public class Message{
		private String sender;
		private String receiver;
		private String messageBody;

		public Message(String sender, String receiver, String messageBody){
			this.sender = sender;
			this.receiver = receiver;
			this.messageBody = messageBody;
		}

		String getSender(){
			return sender;
		}

		String getReceiver(){
			return receiver;
		}

		String getMessageBody(){
			return messageBody;
		}

	}



	//Helper class that sends Messages to Correct Sockets
	public class MessageDelivery extends Thread {
		Server server;
		SecretKey secretKey;
		IvParameterSpec initVect;
		
		public MessageDelivery(Server server, SecretKey secretKey, IvParameterSpec initVect){
			this.server = server;
			this.secretKey = secretKey;
			this.initVect = initVect;

		}

		@Override
		public void run(){

			try{

				while(true){
					Message message = null;
					//Utilizes a Producer-Consumer Design due to Multithreaded Environment
					synchronized(server.toBeDelivered){
						while(server.toBeDelivered.size() == 0){
							server.toBeDelivered.wait();
						}

						message = server.toBeDelivered.pollFirst();
						server.toBeDelivered.notifyAll();
					}

					if (message != null){
						for (HashMap.Entry<String, DataOutputStream> entry : server.clientAddresses.entrySet()){
							if (message.getReceiver().equals(entry.getKey()) 
								&& !message.getSender().equals(message.getReceiver())){
								sendMessage(entry.getValue(),secretKey,initVect,message.getSender()+": "+message.getMessageBody());
							}
						}
					
					}

				}

			}
			catch (UnknownHostException unkwnHstExcept){
				System.out.println("Incorrect IP Address");
				unkwnHstExcept.printStackTrace();
			}
			catch (NoSuchAlgorithmException algExcep){
				System.out.println("Incorrect Algorithm Reference Passed in for Keys");
				algExcep.printStackTrace();
			}
			catch (IOException ioe){
				System.out.println("Stream Error");
				ioe.printStackTrace();
			}
			catch (NoSuchPaddingException e){
					System.out.println("Cipher getInstance didnt work");
					e.printStackTrace();
			}
			catch (InvalidKeyException e){
				System.out.println("Invalid key used for init");
				e.printStackTrace();
			}
			
			catch (IllegalBlockSizeException e){
				System.out.println("doFinal error");
				e.printStackTrace();
			}
			
			catch (BadPaddingException e){
				System.out.println("doFinal error");
				e.printStackTrace();
			}
			
			catch (InterruptedException e){
				System.out.println("Synchronized error");
				e.printStackTrace();
			}
			catch (InvalidAlgorithmParameterException e){
			System.out.println("Algorithm for AES is Invalid");
			e.printStackTrace();
			}

			
			
		}
}







	//Helper class that handles each Client after it connects to Server
	public class ClientThread extends Thread{
		Socket clientSocket;
		Server server;
		SecretKey secretKey;
		byte[] iv;
		IvParameterSpec initVect;

	public ClientThread(Server server, Socket socket, SecretKey secretKey, byte[] iv, IvParameterSpec initVect){
		this.clientSocket = socket;
		this.server = server;
		this.secretKey = secretKey;
		this.iv = iv;
		this.initVect = initVect;

	}

	@Override
	public void run(){
		String incomingMessage;
		String outgoingMessage;
		String clientName;


		try{

			//Public Key from client is received and used to encrypt AES & IV 
			ObjectInputStream objInput = new ObjectInputStream(clientSocket.getInputStream());
			PublicKey clientPublicKey = null;
			clientPublicKey = (PublicKey)objInput.readObject();


			
			DataOutputStream output = new DataOutputStream(clientSocket.getOutputStream());
			DataInputStream input = new DataInputStream(clientSocket.getInputStream());



			//Send AES Key to Client
			Cipher aesCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			aesCipher.init(Cipher.ENCRYPT_MODE,clientPublicKey);
			byte[] encryptedKey = aesCipher.doFinal(secretKey.getEncoded());
			//Send AES 
			output.writeInt(encryptedKey.length);
			output.write(encryptedKey);
			output.flush();

			//Send IV
			byte[] encryptedIV = aesCipher.doFinal(iv);
			output.writeInt(encryptedIV.length);
			output.write(encryptedIV);
			output.flush();




			sendMessage(output, secretKey, initVect,"Welcome to Kingsley's Magnificent Chat!");
			sendMessage(output, secretKey, initVect,"Please send your Username for registration");

			clientName = receiveMessage(input,secretKey,initVect);
			server.clientAddresses.put(clientName, output);


			System.out.println(clientName+" Registered!");
			sendMessage(output,secretKey,initVect,"Thank you for registering!");
			sendMessage(output,secretKey,initVect, "Messages Format: \"Username Message\"");
			sendMessage(output,secretKey,initVect,"You may now start your Secure chat!");

			//Thread is started for Continuos delivery of Messages
			MessageDelivery messageDelivery = new MessageDelivery (server, secretKey, initVect);
			messageDelivery.start();

			while(true){
				incomingMessage = receiveMessage(input, secretKey, initVect);
				String[] splitUpMessage = incomingMessage.split(" ", 3);
				Message message = new Message(splitUpMessage[0],splitUpMessage[1], splitUpMessage[2]);
				synchronized(server.toBeDelivered){
					server.toBeDelivered.add(message);
					server.toBeDelivered.notifyAll();
				}
			}	
		}
		
		catch (NoSuchAlgorithmException e){
			System.out.println("Cipher getInstance didnt work");
			e.printStackTrace();
		}
		catch (NoSuchPaddingException e){
			System.out.println("Cipher getInstance didnt work");
			e.printStackTrace();
		}
		catch (InvalidKeyException e){
			System.out.println("Invalid key used for init");
			e.printStackTrace();
		}
		catch (IllegalBlockSizeException e){
			System.out.println("doFinal error");
			e.printStackTrace();
		}
		catch (BadPaddingException e){
			System.out.println("doFinal error");
			e.printStackTrace();
		}
		catch (ClassNotFoundException e){
			System.out.println("PublicKey Class error");
			e.printStackTrace();
		}
		catch(IOException e){
			System.out.println("Stream Error");
			e.printStackTrace();
		}
		catch (InvalidAlgorithmParameterException e){
			System.out.println("Cipher getInstance didnt work");
			e.printStackTrace();
		}

	}
}






	String username;
	HashMap<String, DataOutputStream> clientAddresses;
	ArrayDeque <Message> toBeDelivered;


	public Server(String serverName) throws IOException, NoSuchAlgorithmException {
		this.username = serverName;
		this.clientAddresses = new HashMap <String,DataOutputStream>();
		this.toBeDelivered = new ArrayDeque <Message>();
	}

	//Helper Method for Encrypting and Sending Messages with AES
	static void sendMessage(DataOutputStream output, SecretKey aesKey, IvParameterSpec initVect, String outgoingMessage) 
	throws NoSuchAlgorithmException, InvalidKeyException, IOException, NoSuchPaddingException,
	IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException  {
		byte[] message = outgoingMessage.getBytes();
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, aesKey, initVect);
		byte[] encryptedMessage = cipher.doFinal(message);
		output.writeInt(encryptedMessage.length);
		output.write(encryptedMessage);
		output.flush();
	}

	////Helper Method for Receiving and Decrypting Messages with AES
	static String receiveMessage(DataInputStream input, SecretKey aesKey, IvParameterSpec initVect)
	throws NoSuchAlgorithmException, InvalidKeyException, IOException, IllegalBlockSizeException,
	NoSuchPaddingException, BadPaddingException,InvalidAlgorithmParameterException {
		int messageSize = input.readInt();
		byte[] encryptedMessage = new byte[messageSize];
		input.read(encryptedMessage);
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE, aesKey, initVect);
		byte[] result = cipher.doFinal(encryptedMessage);
		return new String(result);
	}


	public static void main(String[] args) throws IOException, NoSuchAlgorithmException {

		Server server = new Server(args[0]);
		System.out.println("Server Running...");
		
		Scanner userInput = new Scanner(System.in);

		try{
			ServerSocket serverSocket = new ServerSocket(Integer.parseInt(args[1]));

			//AES Key & IV Generator
			KeyGenerator aesGenerator = KeyGenerator.getInstance("AES");
			aesGenerator.init(128);
			SecretKey aesKey = aesGenerator.generateKey();
			byte[] iv = new byte[16];
			new SecureRandom().nextBytes(iv);
			IvParameterSpec initVect = new IvParameterSpec(iv);




			while(true){
				Socket newClientSocket = serverSocket.accept();
				Thread clientThread = server.new ClientThread(server, newClientSocket, aesKey, iv, initVect);
				clientThread.start();
			}

		}
		catch (UnknownHostException unkwnHstExcept){
			System.out.println("Incorrect IP Address");
			unkwnHstExcept.printStackTrace();
		}
		catch (NoSuchAlgorithmException e){
				System.out.println("Cipher getInstance didnt work");
				e.printStackTrace();
		}
		catch (IOException ioe){
			System.out.println("Creation of Streams was unsuccessful");
			ioe.printStackTrace();
		}
			
	}

}
