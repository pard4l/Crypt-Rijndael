BEGIN { $| = 1; print "1..5\n"; }
END {print "not ok 1\n" unless $loaded;}
use Crypt::Rijndael;
$loaded = 1;
print "ok 1\n";

$plaintext = chr(0) x 32;
for ($i=0; $i<32; $i++) {
  substr($plaintext, $i, 1)=chr($i);
}

$key = chr(0) x 32;
substr($key, 0, 1) = chr(1);

$ecb = new Crypt::Rijndael $key;

$crypted = $ecb->encrypt($plaintext);
print unpack("H*", $crypted) eq "f2258e225d794572393a6484cfced7cf925d1aa18366bcd93c33d104294c8a6f" ? "" : "not ", "ok 2\n";
print $ecb->decrypt($crypted) eq $plaintext ? "" : "not ", "ok 3\n";

$cbc = new Crypt::Rijndael $key, Crypt::Rijndael::MODE_CBC;
$crypted = $cbc->encrypt($plaintext);
print unpack("H*", $crypted) eq "f2258e225d794572393a6484cfced7cfb487a41f6b6286c00c9c8d80cb3ee9f8" ? "" : "not ", "ok 4\n";
$cbc = new Crypt::Rijndael $key, Crypt::Rijndael::MODE_CBC;
print $cbc->decrypt($crypted) eq $plaintext ? "" : "not ", "ok 5\n";
