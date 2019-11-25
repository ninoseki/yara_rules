rule ShadowVoice {
   strings:
      $a = "AndroidManifest.xml"
      $b = /assets\/.{1,30}\.mp3/
      $c = /assets\/.{1,30}\/.{1,30}\.mp3/
      $d = /res\/raw\/.{1,30}\.mp3/
   condition:
      $a and ($b or $c) and $d and filesize > 2MB
}
