
rule tls_keysfrommastersecret
{
	strings:
		$STR1 = { 4? 8d 64 ?4 b8 4? 3b 66 10 0f 86 59 04 00 00 55 4? 89 e5 4? 81 ec c0 00 00 00 66 89 84 ?4 40 01 00 00 4? 89 9c ?4 48 01 00 00 4? 89 9c ?4 80 01 00 00 4? 89 8c ?4 70 01 00 00 4? 89 84 ?4 68 01 00 00 4? 89 b4 ?4 60 01 00 00 4? 89 bc ?4 58 01 00 00 4? 89 8c ?4 50 01 00 00 4? 8b 94 ?4 d8 00 00 00 4? 8d 14 11 4? 89 54 ?4 68 4? 8d 05 6e 89 7f 00 31 db 4? 89 d1 e8 e4 82 ce ff 4? 8b bc ?4 d8 00 00 00 4? 8b 4c ?4 68 4? 39 cf 77 05 4? 89 fa eb 1d  }
	condition:
		$STR1
}

