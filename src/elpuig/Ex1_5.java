package elpuig;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class Ex1_5 {


    public Ex1_5() {

        //Xifrar

        Xifrar xifrar = new Xifrar();
        SecretKey sKey = xifrar.keygenKeyGeneration(128);

        byte[] text = StringToByte("Texto en plano");

        final byte[] xifrartext = Xifrar.encryptData(sKey, text );


        String s = new String(xifrartext, StandardCharsets.UTF_8);
        System.out.println("Encryptado: "+s);

        // Desxifrar

        final byte [] desxifrartext =  Xifrar.decryptData(sKey, xifrartext);
        String a = new String(desxifrartext, StandardCharsets.UTF_8);
        System.out.println("Desencryptado: "+a);

    }

    public byte[] StringToByte(String string) {
        String inputString = string;
        byte[] byteArrray = inputString.getBytes();
        return byteArrray;
    }
}
