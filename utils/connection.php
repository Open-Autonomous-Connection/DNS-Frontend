<!--
 Copyright (C) 2024 Open Autonomous Connection - All Rights Reserved

 You are unauthorized to remove this copyright.
 You have to give Credits to the Author in your project and link this GitHub site: https://github.com/Open-Autonomous-Connection
 See LICENSE-File if exists
-->

<?php

include(__DIR__ . "/../config.php");

global $DATABASE_HOST, $DATABASE_USER, $DATABASE_PASSWORD, $DATABASE_NAME;

$con = mysqli_connect($DATABASE_HOST, $DATABASE_USER, $DATABASE_PASSWORD, $DATABASE_NAME);
if (!$con) echo "Failed to connect";
?>