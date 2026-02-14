Java.perform(()=>{

    var dlopen_func = Process.getModuleByName("libdl.so").getExportByName('android_dlopen_ext')
    var libFound = false
    Interceptor.attach(dlopen_func,{
        onEnter(args){
            if (args[0].readCString().includes('libstartup.so')){
                libFound = true
                console.log(`[!]Loading Library ${args[0].readCString()}`)
            }
        },

        onLeave(ret){
            if (libFound) {
                libFound = false
                
                
                var initHybridFunc = Process.getModuleByName("libstartup.so").base.add(0x3fbbd4)

                console.log(`[+]Hooking Function ${initHybridFunc}`)
                Interceptor.attach(initHybridFunc,{
                    onEnter(args){
                        console.log(`[!]Class Name ${Java.vm.tryGetEnv().getObjectClassName(args[2])}`)


                        var kClass = Java.use("com.facebook.tigon.tigonmns.TigonMNSConfig")
                        var obj_instance = Java.cast(args[2],kClass) // convert object instance pointer to object instance
                        obj_instance.setEnableCertificateVerificationWithProofOfPossession(false)
                        obj_instance.setForceHttp2(true)
                        obj_instance.setTrustSandboxCertificates(true)
                    },
                    onLeave(ret){

                    }
                })
            }
        }
    })
})
