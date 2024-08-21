rule LicenseIBM: IBM_License_file {
   meta:
      description = "Search for IBM License identifier, from SPDX. Found odd it was in several public repos inside .DS_Store files"
      author = "ferasdour"
   strings:
      $h1 = {23 0a 23 20 43 6f 70 79 72 69 67 68 74 20 32 30 ?? ?? 20 49 42 4d 20 49 6e 63 2e 20 41 6c 6c 20 72 69 67 68 74 73 20 72 65 73 65 72 76 65 64 0a}
      $s1 = "# SPDX-License-Identifier: Apache2.0" fullword ascii
   condition:
      uint16(0) == 0x0a23 and all of them
}
