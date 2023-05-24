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
            System.out.println(newPrefix);
            System.out.println("\n");
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

class AppPassWordCrack {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        System.out.println("########################################        Craquage de mot de passe     #################################################### \n");

        int choice = 0;
        while (choice != 1 && choice != 2) {
            System.out.println("++++++++++++++++++++++++++++         Choisissez la méthode de craquage    ++++++++++++++++++++++++++++++++++++++++++++++++++ \n");
            System.out.println("1. Dictionnaire \n");
            System.out.println("\n");
            System.out.println("2. Force brute \n");

            choice = scanner.nextInt();
            scanner.nextLine();

            if (choice != 1 && choice != 2) {
                System.out.println("Veuillez saisir un choix entre 1 et 2.\n");
            }
        }

        PasswordCracker cracker = PasswordCrackerFactory.createPasswordCracker(choice);

        
        int passwordType = 0;
        while (passwordType != 1 && passwordType != 2 && choice==1) {
            System.out.println("Choisissez le type de mot de passe :\n");

            System.out.println("1. Mot de passe normal \n");

            System.out.println("2. Mot de passe haché \n");

            passwordType = scanner.nextInt();

            System.out.println("\n");

            scanner.nextLine();

            System.out.println("\n");

            if (passwordType != 1 && passwordType != 2) {
                System.out.println("Veuillez saisir un choix entre 1 et 2.\n");
            }
        }

        String password = "";
        if (passwordType == 2) {
            System.out.println("Veuillez renseigner le mot de passe haché :\n");
            password = scanner.nextLine();
            System.out.println("\n");
        } else {
            while (password.isEmpty()) {
                System.out.println("Entrez le mot de passe à craquer (maximum 8 caractères) :\n");
                password = scanner.nextLine();
                System.out.println("\n");

                // Vérifier le nombre de caractères du mot de passe
                if (password.length() > 8) {
                    System.out.println("\n");
                    System.out.println("Le mot de passe doit être inférieur ou égal à 8 caractères.\n");
                    password = "";
                }
            }
        }

        boolean passwordFound = cracker.crackPassword(password, 8);

        if (passwordFound) {
            System.out.println("\n");

            System.out.println("Mot de passe trouvé ! \n");
        } else {
            System.out.println("\n");
            System.out.println("Impossible de trouver le mot de passe.\n");
        }

        scanner.close();
    }
}
