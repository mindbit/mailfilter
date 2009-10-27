<?
function expect($stream, $regex) {
	while ($s = fgets($stream)) {
		echo $s;
		flush();
		if (ereg($regex, $s))
			return $s;
	}
	return false;
}

function send($stream, $data) {
	echo $data;
	flush();
	fwrite($stream, $data);
	fflush($stream);
}

$in = fopen("php://stdin", "r");
$sock = fsockopen("127.0.0.1", 8025, $errno, $errstr, 5);
if ($sock === null)
	die();

stream_set_timeout($sock, 15);

expect($sock, "^220 ") || die();

send($sock, "MAIL FROM:<rrendec@post.ro>\r\n");
expect($sock, "^250 ") || die();

send($sock, "RCPT TO:<apache@bat.ines.ro>\r\n");
expect($sock, "^250 ") || die();

send($sock, "DATA\r\n");
expect($sock, "^354 ") || die();

while ($s = fgets($in))
	fwrite($sock, $s);
send($sock, "\r\n.\r\n");
expect($sock, "^250 ") || die();

send($sock, "QUIT\r\n");
expect($sock, "^221 ");

?>
