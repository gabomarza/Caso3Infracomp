package GeneradorDeCarga;

import Ejecucion.AppAgente;
import uniandes.gload.core.Task;

public class TareaConSeguridad extends Task{

	public void execute() {
			
		    AppAgente c= new AppAgente(true);
		    
				c.inicializar();
				c.inicioStuff();
				c.certificacion();
				c.recibeLlaveSimetrica();
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
