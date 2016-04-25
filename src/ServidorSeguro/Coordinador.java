package ServidorSeguro;


import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.Security;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import utils.*;

public class Coordinador {

	private static ServerSocket ss;	
	private static final String MAESTRO = "MAESTRO: ";
	static java.security.cert.X509Certificate certSer; /* acceso default */
	static KeyPair keyPairServidor; /* acceso default */
	/**
	 * Puerto en el cual escucha el servidor.
	 */
	public static final int PUERTO = 8080;
	
	/**
	 * Numero de threads a correr en el servidor
	 */
	public static final int N_THREADS=1;
	
	/**
	 * Tiempo que va a esperar un thread para cliente antes de ser cerrado por inactividad
	 */
	public static final int TIME_OUT=10000;
	/**
	 * @param args
	 */
	public static void main(String[] args) throws Exception{
		// TODO Auto-generated method stub
		
		System.out.println(MAESTRO + "Establezca puerto de conexion:");
		InputStreamReader isr = new InputStreamReader(System.in);
		BufferedReader br = new BufferedReader(isr);
		int ip = Integer.parseInt(br.readLine());
		System.out.println(MAESTRO + "Empezando servidor maestro en puerto " + ip);
		// Adiciona la libreria como un proveedor de seguridad.
		// Necesario para crear llaves.
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());		
		
		int idThread = 0;
		// Crea el socket que escucha en el puerto seleccionado.
		ss = new ServerSocket(ip);
		System.out.println(MAESTRO + "Socket creado.");
		
		keyPairServidor = Seguridad.grsa();
		certSer = Seguridad.gc(keyPairServidor);
		
		while (true) {
			try { 
				// Crea un delegado por cliente. Atiende por conexion. 
				Socket sc = ss.accept();
				System.out.println(MAESTRO + "Cliente " + idThread + " aceptado.");
				Delegado d = new Delegado(sc,idThread);
				idThread++;
				d.start();
			} catch (IOException e) {
				System.out.println(MAESTRO + "Error creando el socket cliente.");
				e.printStackTrace();
			}
		}
	}
		/**
		 * Metodo que atiende a los usuarios.
		 */
		public void iniciarCom() {
			final ExecutorService pool = Executors.newFixedThreadPool(N_THREADS);

			Runnable serverRun = new Runnable(){
				int idActual=0;
				@Override
				public void run() {
					ServerSocket servSock = null;
					int conexionesPerdidas=0;
					try{
						servSock = new ServerSocket(PUERTO);
						System.out.println("BRE IM READY 4 ANYTHING");
						while(true){
							Socket cliente = servSock.accept();
							
							cliente.setSoTimeout(TIME_OUT);
							pool.execute(new Delegado(cliente,idActual));
							idActual++;
						}
					}catch(Exception e){
						System.err.println("Ocurrio un error dado a continuacion");
						//NI IDEA SI SI SON ESTAS
						//conexionesPerdidas++;
						e.printStackTrace();
					}finally{
						try{
						servSock.close();
						}
						catch(Exception e){
							e.printStackTrace();
						}
					}
				}
			};
			Thread serverT = new Thread(serverRun);
			serverT.start();
		}
	
}