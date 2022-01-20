rule jar_with_images {
	meta:
		author = "ferasdour"
		purpose = "There was a java rat with an image file inside it that appears to have been used to prove the attacker's access into a network. This file was shared via virustotal and virusshare, don't want to associate hash because that's bad rule making"
		issues	= "manifest.mf matches manifest of anything"
	strings:
		$jar_manifest = "MANIFEST.MF"	fullword	// needed because jar
		$png_file_ext = ".png"				// can't use file headers inside of zip, using file ext
		$jpg_file_ext = ".jpg"		
                $jpeg_file_ext = ".jpeg"
		$gif_file_ext = ".gif"
		$apk_file = "AndroidManifest.xml"		// false positives due to android apk files containing both java file manifest as well as images
	condition:
		uint32(0) == 0x04034b50 and			// multiple blog posts suggest this method for finding zip file headers, using "at 0" didn't work with clamav.
		$jar_manifest and 
		($png_file_ext or $jpg_file_ext or $jpeg_file_ext or $gif_file_ext) and not
		$apk_file
}
