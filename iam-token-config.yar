rule ibmcloudconfig: CLOUD_CONFIG_FILE {
   meta:
      description = "Search for bearer token left in file from ibmcloud cli, including plugins"
      author = "ferasdour"
   strings:
      $s1 = "IAMToken"
      $s2 = "IAMRefreshToken"
      $s3 = "cloud.ibm.com"
      $h1 = { 7b 0a 20 20 }
   condition:
      $h1 at 0 and
      all of ($s1, $s2, $s3)
}