import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.util.EntityUtils;
import org.apache.http.entity.StringEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;

interface PasswordCracker {
    boolean crackPassword(String password, int maxLength);
}

class BruteForceCracker implements PasswordCracker {
    private static final String Caracteres = "abcdefghijklmnopqrstuvwxyz";

    @Override
    public boolean crackPassword(String password, int maxLength) {
        for (int length = 1; length <= maxLength; length++) {
            if (generateCombinations("", length, password)) {
                return true;
            }
        }
        return false;
    }

    private boolean generateCombinations(String prefix, int length, String targetPassword) {
        if (prefix.equals(targetPassword)) {
            System.out.println("Mot de passe trouvé : " + prefix);
            return true;
        }

        if (length == 0) {
            return false;
        }

        for (int i = 0; i < Caracteres.length(); i++) {
            String newPrefix = prefix + Caracteres.charAt(i);
            if (generateCombinations(newPrefix, length - 1, targetPassword)) {
                return true;
            }
        }

        return false;
    }
}

class PasswordCrackerFactory {
    public static PasswordCracker createPasswordCracker(int choice) {
        if (choice == 1) {
            return new DictionaryCracker("dictionary.txt");
        } else if (choice == 2) {
            return new BruteForceCracker();
        } else {
            throw new IllegalArgumentException("Choix de craquage invalide.");
        }
    }
}

class DictionaryCracker implements PasswordCracker {
    private String dictionaryFile;

    public DictionaryCracker(String dictionaryFile) {
        this.dictionaryFile = dictionaryFile;
    }

    @Override
    public boolean crackPassword(String password, int maxLength) {
        boolean passwordFound = false;

        if (password.length() == 32) {
            // Le mot de passe est haché, on compare les hachages
            try (BufferedReader br = new BufferedReader(new FileReader(dictionaryFile))) {
                String word;
                while ((word = br.readLine()) != null) {
                    if (word.length() <= maxLength) {
                        String hashedWord = hashPassword(word);
                        if (hashedWord.equals(password)) {
                            System.out.println("Mot de passe trouvé : " + word);
                            passwordFound = true;
                            break;
                        }
                    }
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        } else {
            // Le mot de passe est en clair, on compare directement
            try (BufferedReader br = new BufferedReader(new FileReader(dictionaryFile))) {
                String word;
                while ((word = br.readLine()) != null) {
                    if (word.length() <= maxLength) {
                        if (password.equals(word)) {
                            System.out.println("Mot de passe trouvé : " + word);
                            passwordFound = true;
                            break;
                        }
                    }
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        return passwordFound;
    }

    private String hashPassword(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] messageDigest = md.digest(input.getBytes());

            BigInteger no = new BigInteger(1, messageDigest);

            StringBuilder hashText = new StringBuilder(no.toString(16));
            while (hashText.length() < 32) {
                hashText.insert(0, "0");
            }

            return hashText.toString();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }
}

public class CrackPasswordApi {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        System.out.println("Craquage de mot de passe\n");

        int choice = 0;
        while (choice != 1 && choice != 2) {
            System.out.println("Choisissez la méthode de craquage :\n");
            System.out.println("1. Dictionnaire\n");
            System.out.println("2. Force brute\n");

            choice = scanner.nextInt();
            scanner.nextLine();

            if (choice != 1 && choice != 2) {
                System.out.println("Veuillez saisir un choix entre 1 et 2.\n");
            }
        }

        PasswordCracker cracker = PasswordCrackerFactory.createPasswordCracker(choice);

        String password;
        System.out.println("Entrez le mot de passe à craquer :");
        password = scanner.nextLine();

        boolean passwordFound = cracker.crackPassword(password, 8);

        if (passwordFound) {
            System.out.println("Mot de passe trouvé !");
            sendRequestToAPI(password);
        } else {
            System.out.println("Impossible de trouver le mot de passe.");
        }

        scanner.close();
    }

    private static void sendRequestToAPI(String password) {
        CloseableHttpClient httpClient = HttpClients.createDefault();
        String apiUrl = "https://web.facebook.com/?stype=lo&jlou=Afc4Vm7yKg9yy0JjqcexMg5xW-f61wuHp_pfgVm0uUPyNE-ZgmxCCUFGGoVoF8ltOUbm_MB8qRWBw7nv2OAgJA2hmbP62AIPUbYGcEOUBtVHHQ&smuh=11867&lh=Ac8QnsXSl38x7D_Vjos";

        try {
            HttpPost request = new HttpPost(apiUrl);
            StringEntity params = new StringEntity("password=" + password);
            request.addHeader("content-type", "application/x-www-form-urlencoded");
            request.setEntity(params);

            HttpResponse response = httpClient.execute(request);
            HttpEntity entity = response.getEntity();
            String responseBody = EntityUtils.toString(entity);

            System.out.println("Réponse de l'API : " + responseBody);
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try {
                httpClient.close();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }
}
