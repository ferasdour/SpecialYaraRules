rule phishingKits3 {
   meta:
      description = "PhishingKits3: This was found in multiple phishing kits hosted on open/unauthenticated S3 buckets."
      author = "ferasdour"
   strings:
      $s1 = "https://ajax.googleapis.com/ajax/libs/jquery/" ascii
      $s2 = "https://code.jquery.com/jquery-" ascii
      $s3 = "window.location.hash.substr(" ascii
      $s4 = ".substr((" ascii
       
0      $s5 = ").click(function(event" ascii
      $s6 = "Please try again later" ascii
      $r1 = /url:(\s)\Shttps:\/\/.[a-zA-Z0-9-_.]{6,200}/is
      $r2 = /type:(\s|\s')POST',/is
      $s7 = "email:" ascii
      $s8 = "password:" ascii
      $s9 = "btn').html('" ascii
      $header = { (0d 0a | 20 0d 0a 0d 0a | 3c 21 44 4f ) }
   condition:
       $header at 0 and 6 of ($s*) and all of ($r*)
}