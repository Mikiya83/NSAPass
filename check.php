<?php
	require_once('utils.php');
	
	if (!isset($_GET["password"])&&!isset($_GET["meta"])){
		echo 'Invalid parameters';
		exit(1);
	}

	$configs = parse_ini_file('config.ini');
	$servername = $configs['DB_HOST'];
	$port = $configs['DB_PORT'];
	$dbMeta = $configs['DB_META_TABLE'];
	$dbPassword =$configs['DB_PASSWORD_TABLE'];
	$dbName = $configs['DB_NAME'];
	$username = $configs['DB_USER'];
	$password = $configs['DB_PASSWORD'];

	$db = connect($servername, $port, $dbName, $username, $password);

	if (isset($_GET["password"])){
		$pwdPrefix = $_GET["password"];
		$filteredPwd = cleanPwdInput($pwdPrefix);
		$results = retrieveHashes($db, $dbPassword, $filteredPwd);
		printHashesRes($results);
	} else {
		$results = retrieveMeta($db, $dbMeta);
		printMetaRes($results);
	}
?>
