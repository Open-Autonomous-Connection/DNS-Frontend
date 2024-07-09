<!--
 Copyright (C) 2024 Open Autonomous Connection - All Rights Reserved

 You are unauthorized to remove this copyright.
 You have to give Credits to the Author in your project and link this GitHub site: https://github.com/Open-Autonomous-Connection
 See LICENSE-File if exists
-->

<?php

$DOMAIN_PATTERN = '/^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$/';
$TOP_LEVEL_DOMAIN_PATTERN = '/^[A-Za-z]{2,6}$/';

function check_login($con) {
    if (isset($_SESSION["user"]) && isset($_SESSION["pass"])) {
        $user = $_SESSION["user"];
        $pass = $_SESSION["pass"];

        if (!username_exists($con, $user)) {
            logout();
            return null;
        }

        $query = "SELECT * FROM accounts WHERE username = '$user' AND password = '$pass'";
        $result = mysqli_query($con, $query);

        if ($result && mysqli_num_rows($result) > 0) {
            if (!login($con, $user, $pass, true)) {
                logout();
                return null;
            }

            $user_data = mysqli_fetch_assoc($result);
            return $user_data && login($con, $user, $pass, true);
        }
    }

    return null;
}

function logout() {
    unset($_SESSION["user"]);
    unset($_SESSION["pass"]);
}

function list_domains($con, $username) {
    $domains = [];

    // Get the infokeys for the domains associated with the user
    $query = "SELECT infokey FROM accountinfos WHERE username = ? AND type = 'domain'";
    $stmt = mysqli_prepare($con, $query);
    mysqli_stmt_bind_param($stmt, 's', $username);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);

    $infokeys = [];
    while ($row = mysqli_fetch_assoc($result)) {
        $infokeys[] = $row['infokey'];
    }

    // Fetch the domains based on the infokeys
    if (!empty($infokeys)) {
        $placeholders = implode(',', array_fill(0, count($infokeys), '?'));
        $types = str_repeat('s', count($infokeys));

        $query = "SELECT * FROM domains WHERE accesskey IN ($placeholders)";
        $stmt = mysqli_prepare($con, $query);

        // Dynamically bind the parameters
        mysqli_stmt_bind_param($stmt, $types, ...$infokeys);
        mysqli_stmt_execute($stmt);
        $result = mysqli_stmt_get_result($stmt);

        $domains = mysqli_fetch_all($result, MYSQLI_ASSOC);
    }

    return $domains;
}

function list_topleveldomains($con, $username) {
    $query = "SELECT infokey FROM accountinfos WHERE username = ? AND type = 'tld'";
    $stmt = mysqli_prepare($con, $query);
    mysqli_stmt_bind_param($stmt, 's', $username);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);

    $tlds = [];
    while ($row = mysqli_fetch_assoc($result)) {
        $infokey = $row['infokey'];
        $query = "SELECT * FROM topleveldomains WHERE accesskey = ?";
        $stmt = mysqli_prepare($con, $query);
        mysqli_stmt_bind_param($stmt, 's', $infokey);
        mysqli_stmt_execute($stmt);
        $result_tld = mysqli_stmt_get_result($stmt);
        $tlds = array_merge($tlds, mysqli_fetch_all($result_tld, MYSQLI_ASSOC));
    }

    return $tlds;
}

function list_apikeys($con, $username) {
    $query = "SELECT infokey FROM accountinfos WHERE username = ? AND type = 'api'";
    $stmt = mysqli_prepare($con, $query);
    mysqli_stmt_bind_param($stmt, 's', $username);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);

    $apikeys = [];
    while ($row = mysqli_fetch_assoc($result)) {
        $infokey = $row['infokey'];
        $query = "SELECT * FROM apikeys WHERE keyapi = ?";
        $stmt = mysqli_prepare($con, $query);
        mysqli_stmt_bind_param($stmt, 's', $infokey);
        mysqli_stmt_execute($stmt);
        $result_apikey = mysqli_stmt_get_result($stmt);
        $apikeys = array_merge($apikeys, mysqli_fetch_all($result_apikey, MYSQLI_ASSOC));
    }

    return $apikeys;
}

function create_domain($con, $name, $topLevelDomain, $destination, $username) {
    if (!domainRegisteringAllowed($con)) return false;
    if (domain_exists($con, $name, $topLevelDomain)) return false;
    if (strlen($name) < 3 || strlen($name) > 20) return false;
    if (!top_level_domain_exists($con, $topLevelDomain)) return false;
    if (!is_valid_domain($name)) return false;
    if (!is_valid_top_level_domain($topLevelDomain)) return false;
    if (!username_exists($con, $username)) return false;

    $access_key = generate_key($name . "." . $topLevelDomain . "=" . $username);
    $query = "INSERT INTO domains (name, topleveldomain, destination, accesskey) VALUES (?, ?, ?, ?)";
    $stmt = mysqli_prepare($con, $query);
    mysqli_stmt_bind_param($stmt, 'ssss', $name, $topLevelDomain, $destination, $access_key);
    $result = mysqli_stmt_execute($stmt);

    if ($result) {
        $query = "INSERT INTO accountinfos (username, infokey, type) VALUES (?, ?, 'domain')";
        $stmt = mysqli_prepare($con, $query);
        mysqli_stmt_bind_param($stmt, 'ss', $username, $access_key);
        $result = mysqli_stmt_execute($stmt);

        return $result;
    }

    return false;
}

function create_top_level_domain($con, $name, $infoSite, $username) {
    if (!topLevelDomainRegisteringAllowed($con)) return false;
    if (strlen($name) < 3 || strlen($name) > 10) return false;
    if (top_level_domain_exists($con, $name)) return false;
    if (!is_valid_top_level_domain($name)) return false;
    if (!username_exists($con, $username)) return false;

    $access_key = generate_key($infoSite . "." . $name . "=" . $username);
    $query = "INSERT INTO topleveldomains (name, accesskey, info) VALUES (?, ?, ?)";
    $stmt = mysqli_prepare($con, $query);
    mysqli_stmt_bind_param($stmt, 'sss', $name, $access_key, $infoSite);
    $result = mysqli_stmt_execute($stmt);

    if ($result) {
        $query = "INSERT INTO accountinfos (username, infokey, type) VALUES (?, ?, 'tld')";
        $stmt = mysqli_prepare($con, $query);
        mysqli_stmt_bind_param($stmt, 'ss', $username, $access_key);
        $result = mysqli_stmt_execute($stmt);

        return $result;
    }

    return false;
}

function create_api_key($con, $username, $application) {
    if (!username_exists($con, $username)) return false;
    if (has_api_key($con, $username, $application)) return false;

    $currentApiKeyCount = getCurrentApiKeyCount($con, $username);
    $maxApiKeyCount = maxApiKeys($con);

    if ($maxApiKeyCount != -1 && $currentApiKeyCount >= $maxApiKeyCount) return false;

    $apikey = generate_key($username . "=" . $application);
    $query = "INSERT INTO apikeys (username, application, keyapi) VALUES (?, ?, ?)";
    $stmt = mysqli_prepare($con, $query);
    mysqli_stmt_bind_param($stmt, 'sss', $username, $application, $apikey);
    $result = mysqli_stmt_execute($stmt);

    if ($result) {
        $query = "INSERT INTO accountinfos (username, infokey, type) VALUES (?, ?, 'api')";
        $stmt = mysqli_prepare($con, $query);
        mysqli_stmt_bind_param($stmt, 'ss', $username, $apikey);
        $result = mysqli_stmt_execute($stmt);

        return $result;
    }

    return false;
}

function getCurrentApiKeyCount($con, $username) {
    $query = "SELECT COUNT(*) as count FROM apikeys WHERE username = '$username'";
    $result = mysqli_query($con, $query);
    if ($result && $row = mysqli_fetch_assoc($result)) {
        return intval($row['count']);
    }

    return 0;
}

function is_valid_domain(string $name) {
    global $DOMAIN_PATTERN;
    return preg_match($DOMAIN_PATTERN, $name);
}

function is_valid_top_level_domain(string $topLevelDomain) {
    global $TOP_LEVEL_DOMAIN_PATTERN;
    return preg_match($TOP_LEVEL_DOMAIN_PATTERN, $topLevelDomain);
}

function validate_domain_access_key($con, $name, $topLevelDomain, $accessKey) {
    $query = "SELECT * FROM domains WHERE name = '$name' AND topleveldomain = '$topLevelDomain' AND accesskey = '$accessKey'";
    $result = mysqli_query($con, $query);

    return $result && mysqli_num_rows($result) > 0;
}

function validate_top_level_domain_access_key($con, $topLevelDomain, $accessKey) {
    $query = "SELECT * FROM topleveldomains WHERE name = '$topLevelDomain' AND accesskey = '$accessKey'";
    $result = mysqli_query($con, $query);
    return $result && mysqli_num_rows($result) > 0;
}

function domain_exists($con, $name, $topLevelDomain) {
    if (strcasecmp($name, "info") == 0) return true;

    $query = "SELECT * FROM domains WHERE name = '$name' AND topleveldomain = '$topLevelDomain'";
    $result = mysqli_query($con, $query);

    return $result && mysqli_num_rows($result) > 0;
}

function top_level_domain_exists($con, $topLevelDomain) {
    $query = "SELECT * FROM topleveldomains WHERE name = '$topLevelDomain'";
    $result = mysqli_query($con, $query);

    return $result && mysqli_num_rows($result) > 0;
}

function validate_api_key($con, $username, $application, $apikey) {
    if (!username_exists($con, $username)) return false;
    if (!has_api_key($con, $username, $application)) return false;

    $query = "SELECT * FROM apikeys WHERE application = '$application' AND keyapi = '$apikey' AND username = '$username'";
    $result = mysqli_query($con, $query);

    return $result && mysqli_num_rows($result) > 0;
}

function has_api_key($con, $username, $application) {
    if (!username_exists($con, $username)) return false;

    $query = "SELECT * FROM apikeys WHERE application = '$application' AND username = '$username'";
    $result = mysqli_query($con, $query);

    return $result && mysqli_num_rows($result) > 0;
}

function username_exists($con, $username) {
    $query = "SELECT * FROM accounts WHERE username = '$username'";
    $result = mysqli_query($con, $query);

    return $result && mysqli_num_rows($result) > 0;
}

function create_account($con, $username, $password) {
    if (!accountRegisteringAllowed($con)) return false;
    if (username_exists($con, $username)) return false;
    $pw = hash('sha512', $password);

    $query = "INSERT INTO accounts (username, password) VALUES (?, ?)";
    $stmt = mysqli_prepare($con, $query);
    mysqli_stmt_bind_param($stmt, 'ss', $username, $pw);
    $result = mysqli_stmt_execute($stmt);
    return $result;
}

function login($con, $username, $password, $sha = false) {
    if (!username_exists($con, $username)) return false;
    $pw = $password;
    if (!$sha) $pw = hash('sha512', $password);

    $query = "SELECT * FROM accounts WHERE username = '$username' AND password = '$pw'";
    $result = mysqli_query($con, $query);

    return $result && mysqli_num_rows($result) > 0;
}

function generate_key($based) {
    $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    $charactersLength = strlen($characters);
    $randomString = '';
    for ($i = 0; $i < 20; $i++) $randomString .= $characters[random_int(0, $charactersLength - 1)];

    return hash("sha512", $based . $randomString);
}

function delete_api_key($con, $username, $application, $apiKey) {
    if (!username_exists($con, $username)) return false;
    if (!has_api_key($con, $username, $application)) return false;
    if (!validate_api_key($con, $username, $application, $apiKey)) return false;

    $query = "DELETE FROM apikeys WHERE application = ? AND keyapi = ? AND username = ?";
    $stmt = mysqli_prepare($con, $query);
    mysqli_stmt_bind_param($stmt, 'sss', $application, $apiKey, $username);
    $result = mysqli_stmt_execute($stmt);

    if ($result) {
        $query = "DELETE FROM accountinfos WHERE username = ? AND infokey = ? AND type = 'api'";
        $stmt = mysqli_prepare($con, $query);
        mysqli_stmt_bind_param($stmt, 'ss', $username, $apiKey);
        $result = mysqli_stmt_execute($stmt);
    }

    return $result;
}

function delete_domain($con, $name, $topLevelDomain, $accessKey) {
    if (!validate_domain_access_key($con, $name, $topLevelDomain, $accessKey)) return false;

    $query = "DELETE FROM domains WHERE name = ? AND topleveldomain = ? AND accesskey = ?";
    $stmt = mysqli_prepare($con, $query);
    mysqli_stmt_bind_param($stmt, 'sss', $name, $topLevelDomain, $accessKey);
    $result = mysqli_stmt_execute($stmt);

    if ($result) {
        $query = "DELETE FROM accountinfos WHERE infokey = ?";
        $stmt = mysqli_prepare($con, $query);
        mysqli_stmt_bind_param($stmt, 's', $accessKey);
        mysqli_stmt_execute($stmt);
    }

    return $result;
}

function delete_top_level_domain($con, $topLevelDomain, $accessKey) {
    if (!validate_top_level_domain_access_key($con, $topLevelDomain, $accessKey)) return false;

    $query = "DELETE FROM topleveldomains WHERE name = ? AND accesskey = ?";
    $stmt = mysqli_prepare($con, $query);
    mysqli_stmt_bind_param($stmt, 'ss', $topLevelDomain, $accessKey);
    $result = mysqli_stmt_execute($stmt);

    if ($result) {
        $query = "DELETE FROM accountinfos WHERE infokey = ?";
        $stmt = mysqli_prepare($con, $query);
        mysqli_stmt_bind_param($stmt, 's', $accessKey);
        mysqli_stmt_execute($stmt);
    }

    return $result;
}

function delete_account($con, $username) {
    if (!username_exists($con, $username)) return false;

    $query = "SELECT infokey FROM accountinfos WHERE username = ? AND type = 'domain'";
    $stmt = mysqli_prepare($con, $query);
    mysqli_stmt_bind_param($stmt, 's', $username);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);

    while ($row = mysqli_fetch_assoc($result)) {
        $infokey = $row['infokey'];
        $query = "DELETE FROM domains WHERE accesskey = ?";
        $stmt = mysqli_prepare($con, $query);
        mysqli_stmt_bind_param($stmt, 's', $infokey);
        mysqli_stmt_execute($stmt);
    }

    $query = "SELECT infokey FROM accountinfos WHERE username = ? AND type = 'tld'";
    $stmt = mysqli_prepare($con, $query);
    mysqli_stmt_bind_param($stmt, 's', $username);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);

    while ($row = mysqli_fetch_assoc($result)) {
        $infokey = $row['infokey'];
        $query = "DELETE FROM topleveldomains WHERE accesskey = ?";
        $stmt = mysqli_prepare($con, $query);
        mysqli_stmt_bind_param($stmt, 's', $infokey);
        mysqli_stmt_execute($stmt);
    }

    $query = "DELETE FROM apikeys WHERE username = ?";
    $stmt = mysqli_prepare($con, $query);
    mysqli_stmt_bind_param($stmt, 's', $username);
    mysqli_stmt_execute($stmt);

    $query = "DELETE FROM accountinfos WHERE username = ?";
    $stmt = mysqli_prepare($con, $query);
    mysqli_stmt_bind_param($stmt, 's', $username);
    mysqli_stmt_execute($stmt);

    $query = "DELETE FROM accounts WHERE username = ?";
    $stmt = mysqli_prepare($con, $query);
    mysqli_stmt_bind_param($stmt, 's', $username);
    $result = mysqli_stmt_execute($stmt);

    return $result;
}

function getConfigValue($con, $name) {
    $query = "SELECT value FROM config WHERE name = '$name'";
    $result = mysqli_query($con, $query);

    if ($result && $row = mysqli_fetch_assoc($result)) {
        return $row['value'];
    }

    return null;
}

function parseBoolean($value) {
    return filter_var($value, FILTER_VALIDATE_BOOLEAN);
}

function topLevelDomainRegisteringAllowed($con) {
    $value = getConfigValue($con, 'allow_register_tld');
    return $value !== null && parseBoolean(intval($value));
}

function domainRegisteringAllowed($con) {
    $value = getConfigValue($con, 'allow_register_domain');
    return $value !== null && parseBoolean(intval($value));
}

function accountRegisteringAllowed($con) {
    $value = getConfigValue($con, 'allow_register_account');
    return $value !== null && parseBoolean(intval($value));
}

function maxApiKeys($con) {
    $value = getConfigValue($con, 'max_apikeys');
    return $value !== null ? intval($value) : 0;
}

?>