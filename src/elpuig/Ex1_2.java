package elpuig;

import javax.crypto.SecretKey;
import javax.swing.*;
import java.io.File;
import java.security.Key;
import java.security.KeyStore;

public class Ex1_2 {
    public Ex1_2() throws Exception {
        try {
            Xifrar xifrar = new Xifrar();
            String password = "yasinhola";

            //i
            KeyStore keyStore = xifrar.loadKeyStore("C:\\Users\\Yasin\\Desktop\\yasin.ks", password);
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
}
