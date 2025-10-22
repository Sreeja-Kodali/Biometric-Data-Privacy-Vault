import javax.crypto.SecretKey;
import java.io.File;
import java.nio.file.*;
import java.util.Scanner;

public class Main {
	public static void main(String[] args) throws Exception {
		File authDir = new File("authorized_faces");
		if (!authDir.exists())
			authDir.mkdirs();
		double THR = 5000.0;
		Enrollment enroll = new Enrollment(authDir, THR);
		File keyFile = new File("vault.key");
		SecretKey key; 
		if (keyFile.exists()) 
			key = KeyStoreUtil.loadKey(keyFile.toPath());
		else
		    key = KeyStoreUtil.generateAES256();
		if (!keyFile.exists())
			KeyStoreUtil.saveKey(key, keyFile.toPath());
		Vault vault = new Vault(key);

		Scanner sc = new Scanner(System.in);
		boolean unlocked = false;
		while (true) {
			System.out.println("\n1-Enroll 2-Authenticate 3-Encrypt 4-Decrypt 5-Exit > ");
			String op = sc.nextLine().trim();
			if (op.equals("1")) {
				System.out.print("Enroll image path: ");
				System.out.println(enroll.enroll(sc.nextLine().trim()) ? "Enrolled." : "Failed.");
			} else if (op.equals("2")) {
				System.out.print("Authenticate image path: ");
				unlocked = enroll.authenticate(sc.nextLine().trim());
				System.out.println(unlocked ? "Authenticated!" : "Failed.");
			} else if (op.equals("3")) {
				if (!unlocked) {
					System.out.println("Vault locked.");
					continue;
				}
				System.out.print("Src file: ");
				String s = sc.nextLine().trim();
				System.out.print("Dest file: ");
				String d = sc.nextLine().trim();
				try {
					vault.encryptFile(Paths.get(s), Paths.get(d));
					System.out.println("Encrypted.");
				} catch (Exception ex) {
					System.out.println("Error: " + ex);
				}
			} else if (op.equals("4")) {
				if (!unlocked) {
					System.out.println("Vault locked.");
					continue;
				}
				System.out.print("Enc file: ");
				String s = sc.nextLine().trim();
				System.out.print("Dest file: ");
				String d = sc.nextLine().trim();
				try {
					vault.decryptFile(Paths.get(s), Paths.get(d));
					System.out.println("Decrypted.");
				} catch (Exception ex) {
					System.out.println("Error: " + ex);
				}
			} else if (op.equals("5"))
				break;
		}
		sc.close();;
	}
}
