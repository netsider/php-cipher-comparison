<!--
//PHP Password Dissection/Example
//BY: RUSSELL ROUNDS
//DESIGNED FOR PHP 5.5, MYSQL, NGINX (WINDOWS) 
//7-11-2014
//Code executed when "Get Info" is pressed is not mine (found on public forums)
-->
<!DOCTYPE html>
<html lang="en">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" /> <!-- Text will display gibberish if not ISO-8859-1-->
<title>Russell's Super Password Dissection Form</title>
</head>
<body>
<center>
<h2>Russell's Super Password Form</h2>
<form method="post">
<table border="1" width="25%" bordercolor="green">
	<tr>
		<td>Password:</td>
		<td align=center><input type="text" name="password" value="Sometextforpassword"/></td>
	</tr>
	<tr>
		<td align=center><input type="submit" name="debug" value="Get Info" /></td>
		<td align=center><input type="submit" name="submit" value="Submit" /></td>
	</tr>
</table>
</form>
<br/>
	<?php
	if (isset($_POST['submit']))
	{	  
		$userinput=$_POST['password'];
		
		// password_hash()
		$options = [
		'cost' => 11,
		'salt' => mcrypt_create_iv(22, MCRYPT_DEV_URANDOM),
		// 'salt' => 'russiouyuoiyyuiyoyyuiyiuyiyuy',
		];
		echo 'password_hash():<font color="green"><br/>' . $one = password_hash($userinput, PASSWORD_BCRYPT, $options)."<br/>";
		print_r(password_get_info($one));
		echo '<br/></font></br>';

		// mhash()
		$option['cost'] = 10;
		$mhash = bin2hex(mhash(MHASH_WHIRLPOOL, $userinput));
		$mhash2 = mhash(MHASH_WHIRLPOOL, $userinput);
		echo 'mhash()<font color="red"><br/>(succeeded by hash() function)<br/>' . $mhash . '<br/>';
		echo 'password_needs_rehash(): ';
		echo password_needs_rehash($mhash, PASSWORD_DEFAULT, $option);
		// echo '<br/>mhash_get_hash_name(): ';
		// print_r(mhash_get_hash_name($mhash));
		echo '<br/>After Bin2hex: ' . $mhash; 
		echo '<br/>Before Bin2hex: ' . $mhash2; 
		echo '<br/><br/></font>';

		$hashed_password = hash('whirlpool', $userinput);
		if (hash('whirlpool', $userinput) == $hashed_password) 
		{
		echo "<br/>hash():<font color=red><br/>";
		echo '(succeeded by crypt() function- ?)<br/>';
		echo $hashed_password . '<br/>';
		echo '</font><br/><br/>';
		}
		
		// hash_hmac_file(), which calculates the hash via file contents.
		file_put_contents('example.txt', 'The quick brown fox jumped over the lazy dog.');
		echo 'hash_hmac_file():<br/>';
		echo '<font color="red">' . $pb = hash_hmac_file("tiger192,4", 'example.txt', $userinput);
		print_r(password_get_info($pb));
		echo '</font><br/><br/>';
				
		// crypt()
		$third_hashed_password = crypt($userinput);
		if (crypt($userinput, $third_hashed_password) == $third_hashed_password) 
		{
		echo 'crypt():<font color="green"><br/>';
		echo '(succeded by password_hash() function<br/>';
		echo $third_hashed_password . '<br/>';
		print_r(password_get_info($third_hashed_password));
		echo '</font>';
		echo '<br/>';
		echo '<br/>';
		}

		// hash_pbkdf2()
		$iterations = 100000;
		$salt = mcrypt_create_iv(16, MCRYPT_DEV_URANDOM);  //Can also or openssl_random_psuedo_bytes()
		$pbkdf2_hash = hash_pbkdf2("tiger192,4", $userinput, $salt, $iterations, 20);
		$pbkdf2_hash_without_salt = hash_pbkdf2("sha256", $userinput, $iterations, 20);
		echo 'hash_pdkdf2:<br/>(suceeded by all others):<br/>';
		echo '<font color="blue">' . $pbkdf2_hash . '<br/>';
		echo '(with salt randomly created by mcrypt_create_iv)<br/>';
		print_r(password_get_info($pbkdf2_hash));
		echo '<br/></font>';
		echo '<font color="red">' . $pbkdf2_hash_without_salt;
		echo '<br/>(withOUT salt randomly created by mcrypt_create_iv<br/>';
		print_r(password_get_info($pbkdf2_hash_without_salt));	
		echo '</font><br/><br/>';
	
	// Mcrypt Example//AES-256 / CBC / ZeroBytePadding encrypted
	echo '<br/>mcrypt_encrypt: <br/>';
	$key = pack('H*', "bcb04b7e103a0cd8b54763051cef08bc55abe029fdebae5e1d417e2ffb2a00a3");
	echo '<b>Encryption Key: </b>' . $key;
	echo '<br/>';
    # show key size use either 16, 24 or 32 byte keys for AES-128, 192, 256
    echo '<b>Key Size:' . $key_size =  strlen($key);
	echo '<br/></b>';
	echo '<b><font color="red">String to be Encrypted:</b> ' . $userinput . '<br/></font>';
    
    $iv_size = mcrypt_get_iv_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CBC);
    $iv = mcrypt_create_iv($iv_size, MCRYPT_RAND); # create a random IV to use with CBC encoding
    
    $ciphertext = mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $key, $userinput, MCRYPT_MODE_CBC, $iv);# creates a cipher text compatible with AES (Rijndael block size = 128)
	echo 'Before IV & Plainttext Combined:';
	echo '<b>IV:</b> ' . $iv . '<br/>';
	echo '<b>Ciphertext:</b> ' . $ciphertext . '<br/>';
	echo 'After Being Combined:<br/>';
    # prepend the IV for it to be available for decryption
    $ciphertext = $iv . $ciphertext;
    # encode the resulting cipher text so it can be represented by a string
    $ciphertext_base64 = base64_encode($ciphertext);
	echo  '<b>Combined ciphertext & IV (before base64_encode) :</b> ' . $ciphertext . '<br/>';
    echo  '<b>After Base64 Encoded: </b>' . $ciphertext_base64 . '<br/>';
    # Resulting cipher text has no integrity or authenticity added
    # and is not protected against padding oracle attacks.
    echo '<br/>mcrypt_decrypt:<br/>';
    echo '<b>After base64_decode:</b> ' . $ciphertext_dec = base64_decode($ciphertext_base64);
	echo '<br/>';
    $iv_dec = substr($ciphertext_dec, 0, $iv_size); # retrieves the IV
    $ciphertext_dec = substr($ciphertext_dec, $iv_size);# retrieves ciphertext (everything except $iv_size)
    # may remove 00h valued characters from end of plain text
    $userinput_dec = mcrypt_decrypt(MCRYPT_RIJNDAEL_128, $key, $ciphertext_dec, MCRYPT_MODE_CBC, $iv_dec);
    echo '<b>IV size</b>:' . $iv_size . '<br/>';
	echo '<b>ciphertext_decrypted (length of $iv_size removed - removes IV): ' . $ciphertext_dec . '<br/>';
	echo  '<b>IV:</b>' . $iv . '<br/>';
    echo  '<b><font color="red">De-crypted String</b>: ' . $userinput_dec;
	echo '<br/><br/></font>';
			
		
	// NTML Hash
	function ntlm_hash($txt){
        $txt = iconv('UTF-8', 'UTF-16LE', $txt);
        $md4 = bin2hex(mhash(MHASH_MD4, $txt));
        return strtoupper($md4);
	}		
		echo '<font color="red">Function I Found to Compute NTML Hashes - uses mhash():<br/>';
		echo ntlm_hash($userinput);
		echo '<br/><br/></font>';	
	}
	if(!isset($_POST['submit']) && !isset($_POST['debug']))
	{
	echo 'Press Submit to Begin!<br/> Pressing repeatedly will keep producing the same hash<br/>(Otherwise, you will have to enter the exact same password everytime)<br/><br/>';
	}
	?>

<table border=1><tr><td align=center>
<strong>Key:</strong>
<br/>
<span style="color: red">[Red: Do not Use]</span>
<br>
<span style="color: green">[Green: Safe to Use]</span>
<br/>
<span style="color: blue">[Blue: Outdated (But Safe)]</span>
<br/>
<i>pbkdf2() can have the salt randomly generated by mcrypt_create_iv (as shown)</i>
<br/>
<i>password_hash() and crypt() both automatically generate the salt if it isn't specified</i>
<br/>
<b>In a nutshell: <font color="green">Green</font> and <font color="blue">Blue</font> change because a salt is being randomly generated, <br/>so each hashed password is different.  They can be stored safely in a database</b>
<br/>
</td></tr></table>
</center>
<?php
	if (isset($_POST['debug']))
	{
?>

<?php
// Below code is property of it's (unknown) respective author:
/**
 * This code will benchmark your server to determine how high of a cost you can
 * afford. You want to set the highest cost that you can without slowing down
 * you server too much. 10 is a good baseline, and more is good if your servers
 * are fast enough.
 */
$timeTarget = 0.2; 

$cost = 9;
do {
    $cost++;
    $start = microtime(true);
    password_hash("test", PASSWORD_BCRYPT, ["cost" => $cost]);
    $end = microtime(true);
} while (($end - $start) < $timeTarget);

echo "Appropriate Cost Found: " . $cost . "\n";
?>
<br/>
<?php
print "<pre>";
print_r(hash_algos());
print "</pre>";
?>

<?php
/* These salts are examples only, and should not be used verbatim in your code.
   You should generate a distinct, correctly-formatted salt for each password.
*/
echo 'Hash Examples:';
print "<pre>";
if (CRYPT_STD_DES == 1) {
    echo 'Standard DES: ' . crypt('rasmuslerdorf', 'rl') . "\n";
}

if (CRYPT_EXT_DES == 1) {
    echo 'Extended DES: ' . crypt('rasmuslerdorf', '_J9..rasm') . "\n";
}

if (CRYPT_MD5 == 1) {
    echo 'MD5:          ' . crypt('rasmuslerdorf', '$1$rasmusle$') . "\n";
}

if (CRYPT_BLOWFISH == 1) {
    echo 'Blowfish:     ' . crypt('rasmuslerdorf', '$2a$07$usesomesillystringforsalt$') . "\n";
}

if (CRYPT_SHA256 == 1) {
    echo 'SHA-256:      ' . crypt('rasmuslerdorf', '$5$rounds=5000$usesomesillystringforsalt$') . "\n";
}

if (CRYPT_SHA512 == 1) {
    echo 'SHA-512:      ' . crypt('rasmuslerdorf', '$6$rounds=5000$usesomesillystringforsalt$') . "\n";
}
print "/<pre>";
}
?>
</body>
</html>