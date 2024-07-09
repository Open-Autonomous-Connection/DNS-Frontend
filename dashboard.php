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

$username = $_SESSION['user'];
$user_data = check_login($con);

if ($user_data == null) {
    header('Location: index.php');
    die();
}


if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    if (isset($_POST['delete_domain'])) {
        $name = $_POST['domain_name'];
        $tld = $_POST['tld'];
        $accessKey = $_POST['accessKey'];
        delete_domain($con, $name, $tld, $accessKey);
    } elseif (isset($_POST['delete_tld'])) {
        $name = $_POST['tld_name'];
        $accessKey = $_POST['accessKey'];
        delete_top_level_domain($con, $name, $accessKey);
    } elseif (isset($_POST['delete_apikey'])) {
        $application = $_POST['application'];
        $apiKey = $_POST['apiKey'];
        delete_api_key($con, $username, $application, $apiKey);
    } elseif (isset($_POST['delete_account'])) {
        delete_account($con, $username);
        logout($con);
        header('Location: index.php');
        die();
    }
}

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    if (isset($_POST['create_domain'])) {
        if (!domainRegisteringAllowed($con)) {
            echo "No domain registering allowed!";
            die();
        }

        $name = $_POST['domain_name'];
        $tld = $_POST['tld'];
        $destination = $_POST['destination'];
        create_domain($con, $name, $tld, $destination, $username);
    } elseif (isset($_POST['create_tld'])) {
        if (!topLevelDomainRegisteringAllowed($con)) {
            echo "No top level domain registering allowed!";
            die();
        }

        $name = $_POST['tld_name'];
        $infoSite = $_POST['info_site'];
        create_top_level_domain($con, $name, $infoSite, $username);
    } elseif (isset($_POST['create_apikey'])) {
        $application = $_POST['application'];
        create_api_key($con, $username, $application);
    }
}

$domains = list_domains($con, $username);
$tlds = list_topleveldomains($con, $username);
$apikeys = list_apikeys($con, $username);

?>

<head>
    <title>Open Autonomous Connection - Management/Dashboard</title>
    <meta name="charset" content="UTF-8" />
    <meta name="author" content="Open Autonomous Connection" />
    <meta name="description" content="Register here your API Key or (Top level) Domain" />
</head>
<body>
<h1>Welcome, <?php echo $username; ?></h1>

<h2>Your Domains</h2>
<table border="1">
    <tr>
        <th>Name</th>
        <th>Top Level Domain</th>
        <th>Destination</th>
        <th>Access Key</th>
        <th>Action</th>
    </tr>
    <?php foreach ($domains as $domain): ?>
        <tr>
            <td><?php echo $domain['name']; ?></td>
            <td><?php echo $domain['topleveldomain']; ?></td>
            <td><?php echo $domain['destination']; ?></td>
            <td><?php echo $domain['accesskey']; ?></td>
            <td>
                <form method="post">
                    <input type="hidden" name="domain_name" value="<?php echo $domain['name']; ?>">
                    <input type="hidden" name="tld" value="<?php echo $domain['topleveldomain']; ?>">
                    <input type="hidden" name="accessKey" value="<?php echo $domain['accesskey']; ?>">
                    <input type="submit" name="delete_domain" value="Delete">
                </form>
            </td>
        </tr>
    <?php endforeach; ?>
</table>

<h2>Your Top Level Domains</h2>
<table border="1">
    <tr>
        <th>Name</th>
        <th>Info Site</th>
        <th>Access Key</th>
        <th>Action</th>
    </tr>
    <?php foreach ($tlds as $tld): ?>
        <tr>
            <td><?php echo $tld['name']; ?></td>
            <td><?php echo $tld['info']; ?></td>
            <td><?php echo $tld['accesskey']; ?></td>
            <td>
                <form method="post">
                    <input type="hidden" name="tld_name" value="<?php echo $tld['name']; ?>">
                    <input type="hidden" name="accessKey" value="<?php echo $tld['accesskey']; ?>">
                    <input type="submit" name="delete_tld" value="Delete">
                </form>
            </td>
        </tr>
    <?php endforeach; ?>
</table>

<h2>Your API Keys</h2>
<table border="1">
    <tr>
        <th>Application</th>
        <th>API Key</th>
        <th>Action</th>
    </tr>
    <?php foreach ($apikeys as $apikey): ?>
        <tr>
            <td><?php echo $apikey['application']; ?></td>
            <td><?php echo $apikey['keyapi']; ?></td>
            <td>
                <form method="post">
                    <input type="hidden" name="application" value="<?php echo $apikey['application']; ?>">
                    <input type="hidden" name="apiKey" value="<?php echo $apikey['keyapi']; ?>">
                    <input type="submit" name="delete_apikey" value="Delete">
                </form>
            </td>
        </tr>
    <?php endforeach; ?>
</table>

<h2>Create Domain</h2>
<form method="post">
    <label for="domain_name">Domain Name:</label>
    <input type="text" id="domain_name" name="domain_name" required>
    <label for="tld">Top Level Domain:</label>
    <input type="text" id="tld" name="tld" required>
    <label for="destination">Destination:</label>
    <input type="text" id="destination" name="destination" required>
    <input type="submit" name="create_domain" value="Create Domain">
</form>

<h2>Create Top Level Domain</h2>
<form method="post">
    <label for="tld_name">TLD Name:</label>
    <input type="text" id="tld_name" name="tld_name" required>
    <label for="info_site">Info Site:</label>
    <input type="text" id="info_site" name="info_site" required>
    <input type="submit" name="create_tld" value="Create TLD">
</form>

<h2>Create API Key</h2>
<form method="post">
    <label for="application">Application:</label>
    <input type="text" id="application" name="application" required>
    <input type="submit" name="create_apikey" value="Create API Key">
</form>

<h2>Delete Account</h2>
<form method="post">
    <input type="submit" name="delete_account" value="Delete Account">
</form>
</body>
</html>