<?php

class Login extends Controller {

    public function index() {
        $this->view('login/index');
    }

    public function verify() {
        session_start(); // Start the session

        $username = $_POST['username'];
        $password = $_POST['password'];

        // Check if form data is set
        if (empty($username) || empty($password)) {
            die('Username or password not set.');
        }

        // Fetch the user from the database
        require_once 'app/database.php';
        $dbh = db_connect();

        if (!$dbh) {
            die('Database connection failed.');
        }

        $stmt = $dbh->prepare("SELECT * FROM users WHERE username = :username");
        $stmt->bindParam(':username', $username);
        $stmt->execute();
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user) {
            if (password_verify($password, $user['password'])) {
                // Successful login
                $this->logAttempt($username, 'good');

                // Set session variables
                $_SESSION['loggedin'] = true;
                $_SESSION['username'] = $username;

                // Redirect to home page
                header('Location: /home');
                exit();
            } else {
                // Password verification failed
                $this->logAttempt($username, 'bad');
                header('Location: /login?error=invalid_credentials');
                exit();
            }
        } else {
            // User not found
            $this->logAttempt($username, 'bad');
            header('Location: /login?error=invalid_credentials');
            exit();
        }
    }

    private function logAttempt($username, $attempt) {
        // Insert the login attempt into the database
        require_once 'app/database.php';
        $dbh = db_connect();
        
        if (!$dbh) {
            die('Database connection failed.');
        }

        $stmt = $dbh->prepare("INSERT INTO login_attempts (username, attempt) VALUES (:username, :attempt)");
        $stmt->bindParam(':username', $username);
        $stmt->bindParam(':attempt', $attempt);
        $stmt->execute();
    }
}
?>
