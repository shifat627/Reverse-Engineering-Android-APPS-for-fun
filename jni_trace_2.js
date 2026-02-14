
function getModuleInfo(address) {
  const debugSymbol = DebugSymbol.fromAddress(address);

  if (debugSymbol.moduleName) {
    // Add local offset?
    return debugSymbol.toString();
  }

  // When hooking we might get something interesting like the following;
  //  [
  //    {
  //      "base": "0x76fa7000",    <==== [anon:dalvik-free list large object space]
  //      "protection": "rw-",           we don't actually care about this
  //      "size": 536870912
  //    },
  //    {
  //      "base": "0x771e939000", <==== this isn't the actual base, we need to refind that
  //      "file": {
  //        "offset": 663552,
  //         "path": "/apex/com.android.runtime/lib64/bionic/libc.so",
  //         "size": 0
  //      },
  //     "protection": "rwx",
  //     "size": 4096
  //   }
  // ]

  const builtSymbol = {
    base: ptr(0x0),
    moduleName: '',
    path: '',
    size: 0,
  };

  let ranges = Process.enumerateRanges('').filter(
    (range) => range.base <= address && range.base.add(range.size) >= address,
  );

  ranges.forEach((range) => {
    if (range.file) {
      builtSymbol.path = range.file.path;
      const moduleNameChunks = range.file.path.split('/');
      builtSymbol.moduleName = moduleNameChunks[moduleNameChunks.length - 1];

      builtSymbol.base = range.base.sub(range.file.offset);
    }
  });

  ranges = Process.enumerateRanges('').filter(
    (range) => range.base <= builtSymbol.base && range.base.add(range.size) >= builtSymbol.base,
  );

  ranges.forEach((range) => {
    if (builtSymbol.base === ptr(0x0) || builtSymbol.base < range.base) {
      builtSymbol.base = range.base;
    }
    builtSymbol.size += range.size;
  });

  return {base: builtSymbol.base , name : builtSymbol.moduleName , offset: address.sub(builtSymbol.base)};
}

let nativeMethods = {"methods":[]}
Java.perform(()=>{

var JNINativeInterface = [ "NULL", "NULL", "NULL", "NULL", "GetVersion", "DefineClass", "FindClass", "FromReflectedMethod", "FromReflectedField", "ToReflectedMethod", "GetSuperclass", "IsAssignableFrom", "ToReflectedField", "Throw", "ThrowNew", "ExceptionOccurred", "ExceptionDescribe", "ExceptionClear", "FatalError", "PushLocalFrame", "PopLocalFrame", "NewGlobalRef", "DeleteGlobalRef", "DeleteLocalRef", "IsSameObject", "NewLocalRef", "EnsureLocalCapacity", "AllocObject", "NewObject", "NewObjectV", "NewObjectA", "GetObjectClass", "IsInstanceOf", "GetMethodID", "CallObjectMethod", "CallObjectMethodV", "CallObjectMethodA", "CallBooleanMethod", "CallBooleanMethodV", "CallBooleanMethodA", "CallByteMethod", "CallByteMethodV", "CallByteMethodA", "CallCharMethod", "CallCharMethodV", "CallCharMethodA", "CallShortMethod", "CallShortMethodV", "CallShortMethodA", "CallIntMethod", "CallIntMethodV", "CallIntMethodA", "CallLongMethod", "CallLongMethodV", "CallLongMethodA", "CallFloatMethod", "CallFloatMethodV", "CallFloatMethodA", "CallDoubleMethod", "CallDoubleMethodV", "CallDoubleMethodA", "CallVoidMethod", "CallVoidMethodV", "CallVoidMethodA", "CallNonvirtualObjectMethod", "CallNonvirtualObjectMethodV", "CallNonvirtualObjectMethodA", "CallNonvirtualBooleanMethod", "CallNonvirtualBooleanMethodV", "CallNonvirtualBooleanMethodA", "CallNonvirtualByteMethod", "CallNonvirtualByteMethodV", "CallNonvirtualByteMethodA", "CallNonvirtualCharMethod", "CallNonvirtualCharMethodV", "CallNonvirtualCharMethodA", "CallNonvirtualShortMethod", "CallNonvirtualShortMethodV", "CallNonvirtualShortMethodA", "CallNonvirtualIntMethod", "CallNonvirtualIntMethodV", "CallNonvirtualIntMethodA", "CallNonvirtualLongMethod", "CallNonvirtualLongMethodV", "CallNonvirtualLongMethodA", "CallNonvirtualFloatMethod", "CallNonvirtualFloatMethodV", "CallNonvirtualFloatMethodA", "CallNonvirtualDoubleMethod", "CallNonvirtualDoubleMethodV", "CallNonvirtualDoubleMethodA", "CallNonvirtualVoidMethod", "CallNonvirtualVoidMethodV", "CallNonvirtualVoidMethodA", "GetFieldID", "GetObjectField", "GetBooleanField", "GetByteField", "GetCharField", "GetShortField", "GetIntField", "GetLongField", "GetFloatField", "GetDoubleField", "SetObjectField", "SetBooleanField", "SetByteField", "SetCharField", "SetShortField", "SetIntField", "SetLongField", "SetFloatField", "SetDoubleField", "GetStaticMethodID", "CallStaticObjectMethod", "CallStaticObjectMethodV", "CallStaticObjectMethodA", "CallStaticBooleanMethod", "CallStaticBooleanMethodV", "CallStaticBooleanMethodA", "CallStaticByteMethod", "CallStaticByteMethodV", "CallStaticByteMethodA", "CallStaticCharMethod", "CallStaticCharMethodV", "CallStaticCharMethodA", "CallStaticShortMethod", "CallStaticShortMethodV", "CallStaticShortMethodA", "CallStaticIntMethod", "CallStaticIntMethodV", "CallStaticIntMethodA", "CallStaticLongMethod", "CallStaticLongMethodV", "CallStaticLongMethodA", "CallStaticFloatMethod", "CallStaticFloatMethodV", "CallStaticFloatMethodA", "CallStaticDoubleMethod", "CallStaticDoubleMethodV", "CallStaticDoubleMethodA", "CallStaticVoidMethod", "CallStaticVoidMethodV", "CallStaticVoidMethodA", "GetStaticFieldID", "GetStaticObjectField", "GetStaticBooleanField", "GetStaticByteField", "GetStaticCharField", "GetStaticShortField", "GetStaticIntField", "GetStaticLongField", "GetStaticFloatField", "GetStaticDoubleField", "SetStaticObjectField", "SetStaticBooleanField", "SetStaticByteField", "SetStaticCharField", "SetStaticShortField", "SetStaticIntField", "SetStaticLongField", "SetStaticFloatField", "SetStaticDoubleField", "NewString", "GetStringLength", "GetStringChars", "ReleaseStringChars", "NewStringUTF", "GetStringUTFLength", "GetStringUTFChars", "ReleaseStringUTFChars", "GetArrayLength", "NewObjectArray", "GetObjectArrayElement", "SetObjectArrayElement", "NewBooleanArray", "NewByteArray", "NewCharArray", "NewShortArray", "NewIntArray", "NewLongArray", "NewFloatArray", "NewDoubleArray", "GetBooleanArrayElements", "GetByteArrayElements", "GetCharArrayElements", "GetShortArrayElements", "GetIntArrayElements", "GetLongArrayElements", "GetFloatArrayElements", "GetDoubleArrayElements", "ReleaseBooleanArrayElements", "ReleaseByteArrayElements", "ReleaseCharArrayElements", "ReleaseShortArrayElements", "ReleaseIntArrayElements", "ReleaseLongArrayElements", "ReleaseFloatArrayElements", "ReleaseDoubleArrayElements", "GetBooleanArrayRegion", "GetByteArrayRegion", "GetCharArrayRegion", "GetShortArrayRegion", "GetIntArrayRegion", "GetLongArrayRegion", "GetFloatArrayRegion", "GetDoubleArrayRegion", "SetBooleanArrayRegion", "SetByteArrayRegion", "SetCharArrayRegion", "SetShortArrayRegion", "SetIntArrayRegion", "SetLongArrayRegion", "SetFloatArrayRegion", "SetDoubleArrayRegion", "RegisterNatives", "UnregisterNatives", "MonitorEnter", "MonitorExit", "GetJavaVM", "GetStringRegion", "GetStringUTFRegion", "GetPrimitiveArrayCritical", "ReleasePrimitiveArrayCritical", "GetStringCritical", "ReleaseStringCritical", "NewWeakGlobalRef", "DeleteWeakGlobalRef", "ExceptionCheck", "NewDirectByteBuffer", "GetDirectBufferAddress", "GetDirectBufferCapacity", "GetObjectRefType" ]



let addrRegisterNatives = null

const OURLIB = "libcoldstart.so"                     // Replace with yours

 const threadId = Process.getCurrentThreadId;
const ptrSize = Process.pointerSize;
const jniEnv = Java.vm.getEnv().handle;
const jniFunctionTable = jniEnv.readPointer();

addrRegisterNatives = jniFunctionTable.add(Process.pointerSize * JNINativeInterface.indexOf("RegisterNatives")).readPointer();


Interceptor.attach(addrRegisterNatives, {
    // jint RegisterNatives(JNIEnv *env, jclass clazz, const JNINativeMethod *methods, jint nMethods);
    onEnter: function (args) {
       

       
        
        
        
        var class_name = Java.vm.tryGetEnv().getClassName(args[1]);
        

        
        //console.log("\tclazz.name="+class_name)
        
        var nMethods = parseInt(args[3]);
        //console.log("\tnMethods="+nMethods);
        //console.log("\tmethods[]:");


        var methods_ptr = ptr(args[2]);
        
        for (var i = 0; i < nMethods; i++) {
            var name_ptr = methods_ptr.add(i * Process.pointerSize*3).readPointer();
            var methodName = name_ptr.readCString();
            var sig_ptr = methods_ptr.add(i * Process.pointerSize*3 + Process.pointerSize).readPointer();
            var sig = sig_ptr.readCString()
            //console.log("\t\t"+methodName+"(), sig:", sig)
            
            var fnPtr_ptr = methods_ptr.add(i * Process.pointerSize*3 + Process.pointerSize*2).readPointer()
            // var find_module = Process.findModuleByAddress(fnPtr_ptr);
            // var fnPtr_ptr_ghidra = ptr(fnPtr_ptr).sub(find_module.base).add(0x00100000)
            // console.log("\t\t\tfnPtr:", fnPtr_ptr,  " ghidraOffset:", fnPtr_ptr_ghidra);

            var minfo = getModuleInfo(fnPtr_ptr)
            if (minfo.name !== OURLIB){
                return
            }

            nativeMethods["methods"].push(
                {
                    ghidraOffset : minfo['offset'].add(0x00100000),
                    methodName : class_name+"."+methodName,
                    sig
                }
            )
        }
    
}})

})
