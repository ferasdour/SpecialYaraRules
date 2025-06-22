rule ebifFiles {
   meta:
      description = "Found some files listed as .pr extension, header was EBIF. Trying to see is I can detect others."
      author = "ferasdour"
   strings:
      $header = { 45 42 49 46 04 }
   condition:
       $header at 0
}