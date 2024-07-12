<!--
 Copyright (C) 2024 Open Autonomous Connection - All Rights Reserved

 You are unauthorized to remove this copyright.
 You have to give Credits to the Author in your project and link this GitHub site: https://github.com/Open-Autonomous-Connection
 See LICENSE-File if exists
-->

<?php

session_start();
include(__DIR__ . "/../utils/connection.php");
include(__DIR__ . "/../utils/functions.php");

global $con;
$user_data = check_login($con);

if ($user_data != null) {
    header('Location: dashboard.php');
    die();
}

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $user = $_POST["username"];
    $pass = $_POST["password"];

    if (!empty($user) && !empty($pass)) {
        if (!username_exists($con, $user)) echo "Username not exists.";
        else {
            if (login($con, $user, $pass)) {
                $_SESSION['user'] = $user;
                $pw = hash('sha512', $pass);
                $_SESSION['pass'] = $pw;

                header('Location: ../dashboard.php');
                die();
            } else echo "Failed to login. Wrong credentials?";
        }
    } else echo "Please enter username and password";
}

?>

<html>
<head>
    <title>Open Autonomous Connection - Management/Login</title>
    <meta name="charset" content="UTF-8" />
    <meta name="author" content="Open Autonomous Connection" />
    <meta name="description" content="Register here your API Key or (Top level) Domain" />
</head>

<body>

<div id="box">
    <h4>Login</h4>
    <form method="post">
        <input type="text" name="username" placeholder="Username" />
        <input type="password" name="password" placeholder="Password" />
        <input type="submit" value="Login" />
    </form>

    <a href="auth/register.php">Register</a>
</div>

</body>
</html>

<?php
?>
