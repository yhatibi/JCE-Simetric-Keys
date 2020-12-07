package elpuig;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.EmptyStackException;
import java.util.Scanner;

public class Main {
//      Exercici 1


    //Exercici 1.1
    public static   void ex1_1() throws Exception{
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

        //ii
        final byte [] encryptado = Xifrar.encryptDataPub(bytetext, pub);

        //Imprimir Encryptado
        System.out.println("Encryptado: " + new String(encryptado, StandardCharsets.UTF_8));

    }



    //Exercici 1.2

    public static void Ex1_2() throws Exception {
        try {
            Xifrar xifrar = new Xifrar();
            String password = "yasinhola";
            KeyStore keyStore = xifrar.loadKeyStore("C:\\Users\\Yasin\\Desktop\\yasin.ks", password);

            //i

            System.out.println("Tipus de keystore: "+keyStore.getType());
            System.out.println("Mida del magatzem: "+keyStore.size());
            System.out.println("Àlies de totes les claus: "+keyStore.aliases());
            System.out.println("El certificat: "+ keyStore.getCertificate("yasin") );
            System.out.println("L'algorisme de xifrat d’alguna de les claus" + keyStore.isCertificateEntry("yasin"));


            //ii
            SecretKey secretKey = Xifrar.passwordKeyGeneration(password , 128);
            KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(password.toCharArray());
            keyStore.setEntry("yasin", (KeyStore.Entry) secretKey, protParam);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    //Exercici 1.3
    public static void ex1_3() throws Exception {
        String cer = "C:\\Users\\Yasin\\Downloads\\jordi.cer";
        PublicKey publicKey = Xifrar.getPublicKey(cer);
    }


    //Exercici 1.4
    public static void ex1_4() throws Exception{
        Xifrar xifrar = new Xifrar();
        String password = "yasinhola";
        KeyStore keyStore = xifrar.loadKeyStore("C:\\Users\\Yasin\\Desktop\\yasin.ks", password);

        PublicKey publicKey = Xifrar.getPublicKey(keyStore, "yasin", password);

    }

    //Exercici 1.5
    public void ex1_5() throws Exception{
        Xifrar xifrar = new Xifrar();
        Scanner scanner = new Scanner(System.in);
        String password = "yasinhola";
        KeyStore keyStore = xifrar.loadKeyStore("C:\\Users\\Yasin\\Desktop\\yasin.ks", password);

        KeyStore keystore = KeyStore.getInstance("PKCS12");
        keystore.load(this.getClass().getClassLoader().getResourceAsStream("keyFile.p12"), password.toCharArray());
        PrivateKey key = (PrivateKey)keystore.getKey("yasin", password.toCharArray());
        String text = "hola mundo";
        byte[] textenbytes = text.getBytes("UTF8");
        xifrar.signData(textenbytes, key);
    }

    //Exercici 1.6
    public static void ex1_6() throws Exception{
        Xifrar xifrar = new Xifrar();
        Scanner scanner = new Scanner(System.in);
        String password = "yasinhola";
        KeyStore keyStore = xifrar.loadKeyStore("C:\\Users\\Yasin\\Desktop\\yasin.ks", password);

        String text = "hola mundo";
        byte[] textenbytes = text.getBytes("UTF8");

        String sign = "sign";
        byte[] signbytes = text.getBytes("UTF8");
        String cer = "C:\\Users\\Yasin\\Downloads\\jordi.cer";
        PublicKey publicKey = Xifrar.getPublicKey(cer);

        Boolean validate = Xifrar.validateSignature(textenbytes, signbytes, publicKey);

        System.out.println(validate);
    }

    //Exercici 2
    public static void ex2() throws Exception{
        Xifrar xifrar = new Xifrar();
        KeyPair key = xifrar.randomGenerate(1024);

        String text = "hola mundo";
        byte[] textenbytes = text.getBytes("UTF8");


        byte[][] encrypted = xifrar.encryptWrappedData(textenbytes, key.getPublic());

        for (int i = 0; i < encrypted.length; i++) {
            for (int j = 0; j < encrypted[i].length; j++) {
                // get the string value of your byte and print it out
                System.out.println((String.valueOf(encrypted[i][j]).getBytes()));
            }
        }

        byte[] decrypted = xifrar.decryptWrappedData(encrypted , key.getPrivate());

        System.out.println( new String(decrypted , StandardCharsets.UTF_8));



    }


    public static void main(String[] args) throws Exception {
        ex2();



    }
}
