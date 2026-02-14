Java.perform(()=>{

    var func = Process.getModuleByName("").getExportByName('')
    console.log(`[+] Attaching hook at ${func}`)
    Interceptor.attach(func,{ 
    
        onEnter(args){
            var stack = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new())
            console.log("Here is Java stacktrace: " + stack);
            
            
            console.log('\n\nNative Stacktrace:\n' +
            Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n') + '\n');
        },
        
        onLeave(ret){
            
        }
    })
})
