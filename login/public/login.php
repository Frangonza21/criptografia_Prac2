<?php
/**
 * Página de inicio de sesión
 * Verifica credenciales usando password_verify() para comparación segura
 */




session_start();
require_once '../config/database.php';

$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim($_POST['username']);
    $password = $_POST['password'];

    if (empty($username) || empty($password)) {
        $error = 'Por favor ingrese usuario y contraseña';
    } else {
        $stmt = $pdo->prepare("SELECT * FROM users WHERE username = ? OR email = ?");
        $stmt->execute([$username, $username]);
        $user = $stmt->fetch();

        // password_verify() compara la contraseña ingresada con el hash almacenado
        // Es seguro contra ataques de timing
        if ($user && password_verify($password, $user['password'])) {
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['username'] = $user['username'];
            $_SESSION['login_time'] = date('Y-m-d H:i:s');
            
            header('Location: dashboard.php');
            exit;
        } else {
            $error = 'Credenciales inválidas';
        }
    }
}

if ($user && password_verify ($password , $user['password'])) {


 // Generación de un token pseudoaleatorio seguro
 $token_original = "SESION_" . bin2hex(random_bytes(16));

 // Cifrado asimétrico mediante clave pública
 $token_cifrado = cifrarRSA ( $token_original );

 // Descifrado mediante clave privada
 $token_descifrado = descifrarRSA ( $token_cifrado );

 // Asignación de variables de sesión
 $_SESSION ['user_id'] = $user['id'];
 $_SESSION ['username'] = $user['username'];
 $_SESSION ['login_time'] = date('Y-m-d H:i:s');
 $_SESSION ['token_rsa_cifrado'] = $token_cifrado ;
 $_SESSION ['token_rsa_descifrado'] = $token_descifrado ;

 header('Location: dashboard.php');
 exit;
 }


?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="container">
        <div class="card">
            <h2>Login</h2>
            <?php if ($error): ?>
                <div class="alert alert-error"><?php echo $error; ?></div>
            <?php endif; ?>
            <form method="POST">
                <div class="form-group">
                    <label for="username">Usuario o Email</label>
                    <input type="text" id="username" name="username" required>
                </div>
                <div class="form-group">
                    <label for="password">Contraseña</label>
                    <input type="password" id="password" name="password" required>
                </div>
                <button type="submit" class="btn btn-primary">Iniciar Sesión</button>
            </form>
            <p class="link">¿No tienes cuenta? <a href="register.php">Regístrate</a></p>
        </div>
    </div>
</body>
</html>