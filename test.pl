
BEGIN {
    $| = 1;
    print "1..11\n";
}

END {
    print "not ok 1\n" unless $loaded;
}

use Crypt::Serpent;

$loaded = 1;
print "ok 1\n";

$i = 2;

while (<DATA>) {
   if (/KEY=(\S+)\sPT=(\S+)/) {
      my $key = $1;
      my $plaintext  = pack "H*", $2;

      my $crypt = new Crypt::Serpent $key;

      my $ciphertext = $crypt->encrypt($plaintext);
      my $decrypted = $crypt->decrypt($ciphertext);
      
      print $decrypted eq $plaintext ? "" : "not ", "ok " . $i++ . "\n";
   }
}

__DATA__

KEY=ECFEDD62AC69AADDF46FA6C70E5AF3D0 PT=2622B6F83F2842623FC359EE282F9E2B
KEY=260647C22B564CB6D2AD011D6255D768 PT=4DABD61B04BE3BE44B3F2A02E14B3423
KEY=391C44800602149FBD3C43F567343434 PT=48235149D97BB89B60FC9874FCC2A2A2
KEY=9FC66D24D6D499F02F93E4F6A49D92CB PT=B03FDD2935D7410E36824CDDB23E7123
KEY=BF8D192512566350905C5D9A71E85A97 PT=0E5AD314907B6EB6255BAF84CC15172C
KEY=22D9F11D321EDA3897DD256787AF232E PT=B80ABCA172BFA82AC5FC3711A1EF1D26
KEY=5F315B52BF758710ACBFD4C73C5966F9 PT=58C71E59532A75C37EE08EFEB815DC98
KEY=DE2FD18D2013F180375AC3500B7D9A8F PT=550A7394CC455E29E9AC0BC19B4EFA1B
KEY=1729FB060D50A0E0C156A97A8984576A PT=376B32093397DCD36CBB35E2B1D3F006
KEY=A3B82F75DFD30DC7F02ADECF3006F5F0 PT=8541F20131996539909396EAA25C37E2