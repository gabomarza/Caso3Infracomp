package GeneradorDeCarga;

import Ejecucion.AppAgente;
import uniandes.gload.core.Task;

public class TareaConSeguridad extends Task{

	public void execute() {
			
		    AppAgente c= new AppAgente(true);
		    System.out.println("Esta es la consola");
		    
				c.inicializar();
				System.out.println("VA ACA1");
				c.inicioStuff();
				System.out.println("VA ACA2");
				c.certificacion();
				System.out.println("VA ACA3");
				c.recibeLlaveSimetrica();
				System.out.println("VA ACA4");
				c.manejoPosicion();
				System.out.println("Proceso terminado exitosamente");
			
			
	}

	public void fail() {

		System.out.println(Task.MENSAJE_FAIL);
	}

	
	public void success() {

		System.out.println(Task.OK_MESSAGE);
	}



}
