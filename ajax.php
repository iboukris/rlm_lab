<?php 
//error_reporting(E_ALL);
//ini_set('display_errors', '1');
header('Content-Type: application/json');

function db_connect () {
    $sql_uri = 'mysql:host=localhost;dbname=radius;charset=utf8';
    try {
	$p = new PDO($sql_uri, 'radius', 'secret');
    } catch(PDOException $e) {
	return null;
    }
    return $p;
}

function get_scheme() {
	$scheme = json_decode(file_get_contents("scheme.json"));
	return $scheme;
}

class User {
    public function User($name = "") {
        $this->username = $name;
	$this->scheme = get_scheme();
    }
    public $username;
    public $scheme;
    public $items = null;
    function get() {
	$stmt = db_connect();
	if (!isset($stmt)) 
	    return false;
	foreach($this->scheme as $list => $avps ) {
            $q = 'SELECT attribute, value FROM ' . $list
	        	 . ' WHERE username = "' . $this->username . '";';
            foreach ($stmt->query($q) as $data) {
	        if (!isset($avps->$data['attribute'])) {
			$this->items = null;
			return false;
		}
		if (!isset($this->items->$list))
		    $this->items->$list = (object) array();
		$this->items->$list->$data['attribute'] = $data['value'];
	    }
	}
	$stmt = null;
	return true;
    }
    function del() {
        $stmt = db_connect();
	foreach($this->scheme as $list => $avps ) {
		$q = 'DELETE FROM ' . $list . ' WHERE username = "' 
			. $this->username . '";';
        	$stmt->exec($q);
	}
        $stmt = null;
    }
    function set($req) {
        foreach($this->scheme as $list => $avps ) {
             if (!isset($req->$list)) 
                continue;
             $this->items->$list = (object) array();
             foreach($req->$list as $attr => $value) {
                 if (!isset($avps->$attr)) {
                     $this->items = null;
                     return false;
                }
                $this->items->$list->$attr = $value;
             }
        }
	$this->del();
	if (!isset($this->items)) 
	    return true;
        $stmt = db_connect();
        foreach ($this->items as $list => $avps) {
            foreach($avps as $attr => $value) {
                $q = 'INSERT INTO ' . $list . '  values (NULL, "' 
		    . $this->username . '", "' . $attr . '", ":=", "'
                        . $value . '");';
                if ($stmt->exec($q) != 1)
                    return false;
            } 
        }
        $stmt = null;
	return true;
    }
    function to_json($rc) {
        return json_encode(array_merge(array(
		'username' => $this->username, 'rc' => $rc),
			(array)$this->items));
    }
}

$req = json_decode(file_get_contents("php://input"));
if ($req) {
    $res = null;
    $u = new User($req->username);
    switch ($req->action) {
        case "get":
            $res = $u->to_json($u->get());
            break;
        case "set":
            $res = json_encode(array('rc' => $u->set($req)));
    }
    echo $res;
}
else echo json_encode(array('rc' => false));
?> 
