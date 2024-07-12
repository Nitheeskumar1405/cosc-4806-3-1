<?php

class Create extends Controller {

    public function index() {
        $this->view('create/index');
    }

    public function store() {
        // Debugging: Output POST data
        echo '<pre>';
        print_r($_POST);
        echo '</pre>';

        if (!isset($_POST['username']) || !isset($_POST['password'])) {
            die('Username or password not set.');
        }

        $username = $_POST['username'];
        $password = password_hash($_POST['password'], PASSWORD_DEFAULT);

        // Debugging: Check if username and password are processed correctly
        echo 'Username: ' . $username . '<br>';
        echo 'Password Hash: ' . $password . '<br>';

        // Include Database.php and use it
        $databasePath = 'app/database.php';  // Corrected path
        if (!file_exists($databasePath)) {
            die('Database.php file not found at ' . $databasePath);
        }

        require_once $databasePath;

        // Use the existing db_connect function
        $dbh = db_connect();

        if (!$dbh) {
            die('Database connection failed.');
        }

        // Prepare and execute the query
        $stmt = $dbh->prepare("INSERT INTO users (username, password) VALUES (:username, :password)");
        $stmt->bindParam(':username', $username);
        $stmt->bindParam(':password', $password);

        // Debugging: Check if query execution is successful
        if ($stmt->execute()) {
            header('Location: /login');
        } else {
            echo "There was an error creating the account.";
        }
    }
}
?>
