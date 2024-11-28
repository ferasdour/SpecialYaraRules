rule ibmcloudpage: CLOUD_PAGE_FILE {
   meta:
      description = "Search for bearer token left in file from ibmcloud cli, including plugins"
      author = "ferasdour"
   strings:
      $s1 = "IAMToken"
      $s2 = "IAMRefreshToken"
      $s3 = "cloud.ibm.com"
      $s4 = "{"

   condition:
      all of ($s1, $s2, $s3) and ($s4 at 0)
      
}