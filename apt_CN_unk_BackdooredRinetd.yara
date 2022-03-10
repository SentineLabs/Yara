rule apt_CN_unk_backdooredRinetd
{
  meta:
    desc = "Detecting backdoor function in rinetd"
    author = "JAG-S @ SentinelLabs"
    reference = "https://twitter.com/joakimkennedy/status/1501956012793896961?s=20&t=CmeYi-HQ7vMUVn1eCrOwJw"
    hash = "3b0dfabb50627416ab045fec1402aa08830c3b770559608dde65351e9712aefb"
    hash = "756ad13c7b4e27cdd4aefb28281b5785415e10fa4849aadecfbb6ee1b5a97b6d"
    hash = "3efd9290be1b863e072932b6d76bd4b753c9aa1f6659e36f3bbec2e772316e40"
    hash = "b66a52da68ed5ae84ebb13ad7f3b99b5a322315509c1769d6f9bed15a99bbb38"
    hash = "5ca11b1e37c51a219ccba3c665e34004bdd86771872ce808cdcd68b1c3b42811"
    hash = "8e981c2dd2075186b4da85c8d6ee255c85006e139c7ffcdf3143ba32622ba6d1"
  strings:
    $check_update_1 = { 0000BE002000004889C7E886F8FFFF488B45E04889C7E81AF9FFFF488D85B07F }
    $check_update_3 = { EC48980FB68405B0BFFFFF83F08689C28B45EC4898889405B0BFFFFF8345EC01 }
    $check_update_8 = { FF4889C7E835FDFFFF488D8DE0DFFFFF488D95B0BFFFFF488D85E0BFFFFFBE90 }
    $check_update_12 = { 000400004889D7F348AB488D95E0BFFFFFB800000000B9000400004889D7F348 }
    $check_update_15 = { B1FAFFFF488945E048837DE000743C488B55E0488D85B07FFFFF4889D1BA0100 }
    $check_update_18 = { 85B09FFFFFBE9A5E40004889C7B800000000E89EFAFFFF488D85B09FFFFF4889 }
    $check_update_19 = { 5E40004889C7B800000000E825FBFFFF488D85E0BFFFFFBE985E40004889C7E8 }
    $check_update_21 = { FFFF0FB60084C0743DEB0CBFE8030000E842FCFFFFEB99488D95B07FFFFF488D }
    $cmd = "/bin/sh -c \"$(curl -fsSL %s)\"" ascii wide fullword 

    $generic_stack_string = { C6 85 [2] FF FF }
  condition:
    (#generic_stack_string >= 30)
    and 
    (
      5 of ($check_update*) 
      or
      $cmd
    )
}
