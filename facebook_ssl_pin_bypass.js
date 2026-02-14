Java.perform(()=>{
var CertificateVerifier = Java.use("com.facebook.mobilenetwork.internal.certificateverifier.CertificateVerifier");
CertificateVerifier["verifyCrlSignature"].implementation = function (str, str2, str3) {
    console.log(`CertificateVerifier.verifyCrlSignature is called: str=${str}, str2=${str2}, str3=${str3}`);
    let result = this["verifyCrlSignature"](str, str2, str3);
    console.log(`CertificateVerifier.verifyCrlSignature result=${result}`);
    return result;
};

})
