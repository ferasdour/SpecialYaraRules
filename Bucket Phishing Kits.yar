rule phishingKits3 {
   meta:
      description = "PhishingKits3"
      author = "ferasdour"
   strings:
      $s1 = "https://ajax.googleapis.com/ajax/libs/jquery/" ascii
      $s2 = "https://code.jquery.com/jquery-" ascii
      $s3 = "window.location.hash.substr(" ascii
      $s4 = ".substr((" ascii
      $s5 = ").click(function(event" ascii
      $s6 = "Please try again later" ascii
      $r1 = /url:(\s)\Shttps:\/\/.[a-zA-Z0-9-_.]{6,200}/is
      $s7 = "type: 'POST'," ascii
      $s8 = "email:" ascii
      $s9 = "password:" ascii
      $s10 = "btn').html('" ascii
      $header = { (0d 0a | 20 0d 0a 0d 0a) }
   condition:
       $header at 0 and 7 of ($s*) and $r1
}