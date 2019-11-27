rule ShadowVoice {
   strings:
      $manifest = "AndroidManifest.xml"
      $assets_mp3_a = /assets\/.{1,30}\.mp3/
      $assets_mp3_b = /assets\/.{1,30}\/.{1,30}\.mp3/
      $res_mp3 = /res\/raw\/.{1,30}\.mp3/
   condition:
      $manifest and ($assets_mp3_a or $assets_mp3_b) and $res_mp3 and filesize > 2MB
}
