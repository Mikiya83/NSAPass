<?php
	$SEPARATOR = ':';

	class pwdResult {
		public $hashPwd;
		public $count;
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
			echo substr($resValue->hash, 5),$SEPARATOR,$resValue->count,'/';
		}
	}
	
	function retrieveMeta($db, $dbMeta){
		$sql = 'SELECT * FROM '.$dbMeta;
		$sth = $db->prepare($sql);
		$sth->execute(array());
		$results = $sth->fetchAll(PDO::FETCH_CLASS, "metaResult");
		return $results;
	}
	
	function retrieveHashes($db, $dbPassword, $dbMeta, $filteredPwdHash){
		$sql = 'SELECT * FROM '.$dbPassword.' WHERE hash LIKE ?';
		$sth = $db->prepare($sql);
		$sth->execute(array($filteredPwdHash.'%'));
		$results = $sth->fetchAll(PDO::FETCH_CLASS, "pwdResult");
		
		// Increment meta
		$resMeta = retrieveMeta($db,$dbMeta);
		$cnt = ($resMeta[0]->req_count)+1;
		$sqlMeta = 'UPDATE '.$dbMeta.' SET req_count = ? WHERE id = ?';
		$sthMeta = $db->prepare($sqlMeta);
		$sthMeta->execute(array($cnt, $resMeta[0]->id));
		
		return $results;
	}
?>
