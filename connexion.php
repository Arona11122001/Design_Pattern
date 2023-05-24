<?php
// Identifiant de l'admin correct
$correctAdminId = "admin123";

// Mot de passe correct
$correctPassword = "abc";

// Vérifier si un identifiant d'admin et un mot de passe ont été envoyés
if (isset($_POST['adminId']) && isset($_POST['password'])) {
    // Récupérer l'identifiant d'admin et le mot de passe envoyés
    $adminId = $_POST['adminId'];
    $password = $_POST['password'];

    // Vérifier si l'identifiant de l'admin et le mot de passe correspondent
    if ($adminId === $correctAdminId && $password === $correctPassword) {
        // Identifiant de l'admin et mot de passe corrects
        echo "SUCCESS";
        exit(); // Terminer l'exécution du script après l'affichage de "SUCCESS"
    } else {
        // Identifiant de l'admin ou mot de passe incorrects
        echo "FAILURE";
    }
}
?>


<!DOCTYPE html>
<html>
<head>
    <title>Formulaire de connexion</title>
</head>
<body>
    <h2>Connexion</h2>
    <form method="POST" action="">
        <label for="adminId">Identifiant :</label>
        <input type="text" name="adminId" id="adminId" required><br><br>
        
        <label for="password">Mot de passe :</label>
        <input type="password" name="password" id="password" required><br><br>
        
        <input type="submit" value="Se connecter">
    </form>
</body>
</html>
