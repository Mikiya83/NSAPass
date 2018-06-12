<?php
	$SEPARATOR = ':';

	class pwdResult {
		public $hashPwd;
		public $counter;
	}
	
	class metaResult {
		public $id;
		public $req_count;
		public $db_version;
		public $nb_password;
	}
	
	function cleanPwdInput($input){
		$inputPwd = strtoupper(htmlspecialchars((string) $input));
		if (strlen($inputPwd) == 5 && ctype_xdigit($inputPwd)) {
			$filtered = $inputPwd;
		} else {
			echo 'Invalid parameters';
			exit(1);
		}
		return $filtered;
	}
	
	function connect($servername, $port, $dbName, $username, $password){
		try {
			$conn = new PDO("mysql:host=$servername;port=$port;dbname=$dbName", $username, $password);
			// set the PDO error mode to exception
			$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);	
			return $conn;
		}
		catch(PDOException $e){
			echo "Connection failed: " . $e->getMessage();
			exit(1);
		}
	}
		
	function printMetaRes($results) {
		global $SEPARATOR;
		foreach ($results as $resValue){
			echo json_encode($resValue);
		}
	}
	
	function printHashesRes($results) {
		global $SEPARATOR;
		foreach ($results as $resValue){
			echo $resValue->hash,$SEPARATOR,$resValue->counter,PHP_EOL;
		}
	}
	
	function retrieveMeta($db, $dbMeta){
		$sql = 'SELECT * FROM '.$dbMeta;
		$sth = $db->prepare($sql);
		$sth->execute(array());
		$results = $sth->fetchAll(PDO::FETCH_CLASS, "metaResult");
		return $results;
	}
	
	function retrieveHashes($db, $dbPassword, $filteredPwdHash){
		$sql = 'SELECT * FROM '.$dbPassword.' WHERE hash LIKE ?';
		$sth = $db->prepare($sql);
		$sth->execute(array($filteredPwdHash.'%'));
		$results = $sth->fetchAll(PDO::FETCH_CLASS, "pwdResult");
		return $results;
	}
?>
