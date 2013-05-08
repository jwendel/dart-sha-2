import "dart:io";

main() {
  stdin
  .transform(new StringDecoder())
  .transform(new LineTransformer())
  .listen((String line) {
    print("const [ " + line.replaceAllMapped(new RegExp(r"(..)"), (_) => "0x${_[0]}, ") + " ],");
    
  });
  
}
