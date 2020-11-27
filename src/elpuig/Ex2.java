package elpuig;

import javax.crypto.SecretKey;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;

public class Ex2 {

    public Ex2() throws IOException {

        Path path = Paths.get("C:\\Users\\Yasin\\Downloads\\textamagat");
        byte[] textenbytes = Files.readAllBytes(path);
        File f = new File("C:\\Users\\Yasin\\Downloads\\clausA4.txt");
        FileReader fr = new FileReader(f);
        BufferedReader br =  new BufferedReader(fr);
        String line = br.readLine();
        while(line != null ) { //fins que no hi ha més línies a llegir
            //fer alguna cosa amb la línia llegida
            try {
                SecretKey skey = Xifrar.passwordKeyGeneration(line, 128);
                final byte [] desxifrartext =  Xifrar.decryptData(skey, textenbytes);
                String a = new String(desxifrartext, StandardCharsets.UTF_8);
                System.out.println("Password: " + line);
                System.out.println("Desencryptado: "+a);
                break;
                //següent línia
            } catch (Exception e) {
                System.out.println("Error! "+line+" no es la contraseña.");
                line = br.readLine();
            }
        }
    }
}
