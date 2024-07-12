<?php
session_start(); // Start the session

// Check if the user is logged in
if (!isset($_SESSION['loggedin']) || $_SESSION['loggedin'] !== true) {
    header('Location: /login');
    exit();
}

require_once 'app/views/templates/header.php';
?>
<div class="container">
    <div class="page-header" id="banner">
        <div class="row">
            <div class="col-lg-12">
                <h1>Hey, <?php echo htmlspecialchars($_SESSION['username']); ?></h1>
                <p class="lead"> <?= date("F jS, Y"); ?></p>
            </div>
        </div>
    </div>
    <div class="row">
        <div class="col-lg-12">
            <p><a href="/logout" class="btn btn-primary">Click here to logout</a></p>
        </div>
    </div>
</div>
<?php require_once 'app/views/templates/footer.php' ?>
