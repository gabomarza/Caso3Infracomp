package ServidorSeguro;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.lang.management.ManagementFactory;
import java.net.Socket;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.io.File;
import java.io.FileWriter;

import javax.crypto.SecretKey;

import com.csvreader.CsvWriter;

import utils.*;
import jxl.*;
import jxl.write.WritableSheet;
import jxl.write.WritableWorkbook;

public class Delegado extends Thread {
	// Constantes
	public static final String MAESTRO = "MAESTRO";
	public static final String STATUS = "ESTADO";
	public static final String OK = "OK";
	public static final String ALGORITMOS = "ALGORITMOS";
	public static final String HMACMD5 = "HMACMD5";
	public static final String HMACSHA1 = "HMACSHA1";
	public static final String HMACSHA256 = "HMACSHA256";
	public static final String CERTSRV = "CERTSRV";
	public static final String CERCLNT = "CERCLNT";
	public static final String SEPARADOR = ":";
	public static final String HOLA = "HOLA";
	public static final String INICIO = "INICIO";
	public static final String ERROR = "ERROR";
	public static final String ERRORPRT = "ERROR EN PROTOCOLO:";
	public static final String REC = "recibio-";
	// Atributos
	private Socket sc = null;
	private String dlg;
	private int id;
	
	Delegado (Socket csP, int idP) {
		sc = csP;
		dlg = new String("dlg " + idP + ": ");
		id=idP;
	}
	
	public void run() {
		Long tim = System.currentTimeMillis();
		String me = new String(STATUS+SEPARADOR+ERROR);
		String mok = new String(STATUS+SEPARADOR+OK);
		String mt;
		String linea;
		System.out.println(MAESTRO + "Cliente " + dlg + " aceptado.");
	    System.out.println(dlg + "Empezando atencion.");
	    String archivo = "C:/Users/Eduardo/git/Caso3Infracomp/docs/datos.csv";
	    boolean yaExiste = new File(archivo).exists();
	        try {
	        	CsvWriter csv = new CsvWriter(new FileWriter(archivo,true), ',');
				PrintWriter ac = new PrintWriter(sc.getOutputStream() , true);
				BufferedReader dc = new BufferedReader(new InputStreamReader(sc.getInputStream()));
				if(!yaExiste)
				{
					csv.write("ID usuario");
					csv.write("Tiempo creacion de certificado");
					csv.write("Tiempo ACT");
					csv.write("Tiempo Total");
					csv.write("Tiempo Real");
					csv.endRecord();
				}
				csv.write(""+id);
				//Se crea el libro Excel
				//WritableWorkbook workbookwrite = Workbook.createWorkbook(new java.io.File("docs/Data4.xls"));
				 
				//Se crea una nueva hoja dentro del libro
				//WritableSheet sheet = workbookwrite.createSheet("HojaEjemplo", 0);
				 
				//Creamos celdas de varios tipos

				/***** Fase 1: Inicio *****/
				linea = dc.readLine();
				if (!linea.equals(HOLA)) {
					ac.println(me);
			        sc.close();
					throw new Exception(dlg + ERRORPRT + REC + linea +"-terminando.");
				}
				System.out.println(dlg + REC + linea + "-continuando.");
				ac.println(INICIO);

				/***** Fase 2: Algoritmos *****/
				linea = dc.readLine();
				if (!(linea.contains(SEPARADOR) && linea.split(SEPARADOR)[0].equals(ALGORITMOS))) {
					ac.println(me);
					sc.close();
					throw new Exception(dlg + ERRORPRT + REC + linea +"-terminando.");
				}
				
				String[] algoritmos = linea.split(SEPARADOR);
				if (!algoritmos[1].equals(Seguridad.DES) && !algoritmos[1].equals(Seguridad.AES) &&
					!algoritmos[1].equals(Seguridad.BLOWFISH) && !algoritmos[1].equals(Seguridad.RC4)){
					ac.println(STATUS+SEPARADOR+ERROR);
					sc.close();
					throw new Exception(dlg + ERRORPRT + "Alg.Simetrico" + REC + algoritmos + "-terminando.");
				}
				if (!algoritmos[2].equals(Seguridad.RSA)) {
					ac.println(me);
					sc.close();
					throw new Exception(dlg + ERRORPRT + "Alg.Asimetrico." + REC + algoritmos + "-terminando.");
				}
				if (!(algoritmos[3].equals(HMACMD5) || algoritmos[3].equals(HMACSHA1) ||
					  algoritmos[3].equals(HMACSHA256))) {
					ac.println(me);
					sc.close();
					throw new Exception(dlg + ERRORPRT + "AlgHash." + REC + algoritmos + "-terminando.");
				}
				System.out.println(dlg + REC + linea + "-continuando.");
				ac.println(mok);

				/***** Fase 3: Recibe certificado del cliente *****/


				//---------------------medidores de tiempo------------------------
				Long timFinCert = null;
				Long timIniCert = System.currentTimeMillis();
				linea = dc.readLine();
				mt = new String(CERCLNT + SEPARADOR);
				if (!(linea.equals(mt))) {
					ac.println(me);
					sc.close();
					throw new Exception(dlg + ERRORPRT + "CERCLNT." + REC + linea + "-terminando.");
				}
				System.out.println(dlg + REC + mt + "-continuando.");
				int offset = 0;
				byte[] certificadoServidorBytes = new byte[520];
				int numBytesLeidos = sc.getInputStream().read(certificadoServidorBytes,offset,520-offset);
				if (numBytesLeidos<=0) {
					ac.println(me);
					sc.close();
					throw new Exception(dlg + "Error recibiendo certificado. terminando.");					
				}
				CertificateFactory creador = CertificateFactory.getInstance("X.509");
				InputStream in = new ByteArrayInputStream(certificadoServidorBytes);
				X509Certificate certificadoCliente = (X509Certificate)creador.generateCertificate(in);
				System.out.println(dlg + "recibio certificado del cliente. continuando.");
				
				/***** Fase 4: Envia certificado del servidor *****/
				mt= new String(CERTSRV + SEPARADOR);
				ac.println(mt);
				byte[] mybyte = Coordinador.certSer.getEncoded( );
				sc.getOutputStream( ).write( mybyte );
				sc.getOutputStream( ).flush( );
				System.out.println(dlg + "envio certificado del servidor. continuando.");
				linea = dc.readLine();
				if (!(linea.equals(mok))) {
					ac.println(me);
					throw new Exception(dlg + ERRORPRT + REC + linea + "-terminando.");
				}
				System.out.println(dlg + "recibio-" + linea + "-continuando.");
				
				//---------------------medidores de tiempo------------------------
				timFinCert = System.currentTimeMillis();
				timFinCert-=timIniCert;
				csv.write(""+timFinCert);
				//sheet.addCell(new jxl.write.Number(id, 0, timIniCert));
				
				/***** Fase 5: Envia llave simetrica *****/
				SecretKey simetrica = Seguridad.kgg(algoritmos[1]);
				byte [ ] ciphertext1 = Seguridad.ae(simetrica.getEncoded(), 
						                 certificadoCliente.getPublicKey(), algoritmos[2]);
				ac.println("DATA:" + Transformacion.transformar(ciphertext1));
				System.out.println(dlg + "envio llave simetrica al cliente. continuado.");
				
				/***** Fase 6: Confirma llave simetrica *****/
				linea = dc.readLine();
				byte[] llaveS = Seguridad.ad(
						Transformacion.destransformar(linea.split(SEPARADOR)[1]), Coordinador.keyPairServidor.getPrivate(), algoritmos[2]);
				if (!Transformacion.transformar(llaveS).equals(Transformacion.transformar(simetrica.getEncoded()))) {
					ac.println(me);
					throw new Exception(dlg + "Error confirmando llave. terminando.");
				}
				ac.println(mok);
				
				/***** Fase 7: Actualizacion del agente *****/
				Long timFinACT = null;
				Long timIniACT = System.currentTimeMillis();
				
				linea = dc.readLine();
				if (!(linea.contains(SEPARADOR) && linea.split(SEPARADOR)[0].equals("ACT1"))) {
					ac.println(me);
					throw new Exception(dlg + "Error en ACT1. terminando.");
				}
				String datos = new String(Seguridad.sd(
						Transformacion.destransformar( linea.split(SEPARADOR)[1]), simetrica, algoritmos[1]));
				linea = dc.readLine();
				if (!(linea.contains(SEPARADOR) && linea.split(SEPARADOR)[0].equals("ACT2"))) {
					ac.println(me);
					throw new Exception(dlg + "Error en ACT2. terminando.");
				}
				System.out.println(dlg + "descifro informacion-" + datos +  "-continuado.");
				byte[] hmac = Seguridad.ad(
						Transformacion.destransformar( linea.split(SEPARADOR)[1]), 
						certificadoCliente.getPublicKey(), algoritmos[2]);
				boolean verificacion = Seguridad.verificarIntegridad(
						                 datos.getBytes(), simetrica, algoritmos[3], hmac);
				if (verificacion) {
					System.out.println(dlg + "verificacion de integridad:OK. -continuado.");
					ac.println(mok);
				} else {
					ac.println(me);
					throw new Exception(dlg + "Error en verificacion de integridad. -terminando.");
				}
				timFinACT = System.currentTimeMillis();
				timFinACT -= timIniACT;
				//sheet.addCell(new jxl.write.Number(id, 1, timIniACT));
				csv.write(""+timFinACT);
		        sc.close();
		        System.out.println(dlg + "Termino exitosamente.");

		        Long timTotal = System.currentTimeMillis();
		        timTotal-=tim;
				csv.write(""+timTotal);
				Long timeReal = ManagementFactory.getThreadMXBean().getThreadCpuTime(this.getId());
				//IMPRIMIR EN CSV
				csv.write(""+timeReal);
				csv.endRecord();
				csv.close();
	        } catch (Exception e) {
	          e.printStackTrace();
	        }
	}
}