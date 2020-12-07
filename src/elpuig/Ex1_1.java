package elpuig;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Scanner;

public class Ex1_1 {

    public Ex1_1() throws IOException {
        try {
            Xifrar xifrar = new Xifrar();
            Scanner scanner = new Scanner(System.in);

            //i
            KeyPair skey1 = xifrar.randomGenerate(1024);

            //ii
            System.out.println("Escribe1: ");
            String text = scanner.nextLine();
            final byte [] bytetext = text.getBytes("UTF8");

            //iii
            PublicKey pub = skey1.getPublic();
            PrivateKey priv = skey1.getPrivate();

            //ii
            final byte [] encryptado = Xifrar.encryptDataPub(bytetext, pub);

            //Imprimir Encryptado
            String s = new String(encryptado, StandardCharsets.UTF_8);
            System.out.println("Encryptado: "+ s);


        } catch(Exception e) {
            e.printStackTrace();
        }
    }
}
