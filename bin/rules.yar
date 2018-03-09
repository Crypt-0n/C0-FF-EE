rule Win32_Aybo_B {

    meta: 
        author = "jlequen"
        info = "jlequen@crypt-0n.fr"
        malpedia_version = "20170621"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings:
        $1 = "Accept-Language: ru-RU,ru;q=0.9,en;q=0.8"
        $2 = "http://h6i4ze366rr5mnx2.onion/0942c3aad278ce5ea571a61712b4506a.php"
		$3 = "http://88.214.207.83/classes/s.php"
		$4 = "name=\"Security Fix\" protocol=TCP dir=in localport=445 action=block"

    condition:
        all of them
}

rule WannaCry {

    meta: 
        author = "jlequen"
        info = "jlequen@crypt-0n.fr"
        malpedia_version = "20170621"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings:
        $1 = "http://www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com"
		$2 = "mssecsvc.exe"
		$3 = "mssecsvc2.0"
		$4 = "qeriuwjhrf"
		$5 = "Microsoft Security Center (2.0) Service"

    condition:
        all of them
}

rule Suspicious_UPX {

    meta: 
        author = "jlequen"
        info = "jlequen@crypt-0n.fr"
        malpedia_version = "20170621"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings:
        $1 = "UPX0"
		$2 = "UPX1"

    condition:
        all of them
}