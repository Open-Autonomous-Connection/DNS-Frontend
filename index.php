<!--
 Copyright (C) 2024 Open Autonomous Connection - All Rights Reserved

 You are unauthorized to remove this copyright.
 You have to give Credits to the Author in your project and link this GitHub site: https://github.com/Open-Autonomous-Connection
 See LICENSE-File if exists
-->

<?php
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

session_start();
include(__DIR__ . "/utils/connection.php");
include(__DIR__ . "/utils/functions.php");

global $con;
$user_data = check_login($con);

if ($user_data != null) {
    header('Location: dashboard.php');
    die();
}

?>

<html>
<head>
    <title>Open Autonomous Connection - Management</title>
    <meta name="charset" content="UTF-8" />
    <meta name="author" content="Open Autonomous Connection" />
    <meta name="description" content="Register here your API Key or (Top level) Domain" />
    <meta name="keywords" content="domain,api,oac,registration,key,host,manager,management" />
</head>
<body>
<a href="auth/register.php">Register</a>
<a href="auth/login.php">Login</a>
</body>
</html>