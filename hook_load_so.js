Java.perform(function () {
    console.log("[*] Starting SO load monitoring...");
    
    // 获取函数地址
    var dlopen = Module.findExportByName(null, "dlopen");
    var android_dlopen_ext = Module.findExportByName(null, "android_dlopen_ext");
    
    console.log("[*] dlopen address:", dlopen);
    console.log("[*] android_dlopen_ext address:", android_dlopen_ext);
    
    if (dlopen) {
        Interceptor.attach(dlopen, {
            onEnter: function (args) {
                this.path_ptr = args[0];  // 保存到this中，便于onLeave使用
                
                // 检查指针是否有效
                if (!this.path_ptr || this.path_ptr.isNull()) {
                    console.log("[dlopen] null path pointer");
                    return;
                }
                
                try {
                    var path = this.path_ptr.readCString();
                    if (path) {
                        // console.log("[dlopen] Loading:", path);
                        // 可选：打印调用栈
                        // console.log(Thread.backtrace(this.context, Backtracer.ACCURATE)
                        //           .map(DebugSymbol.fromAddress).join('\n'));
                    } else {
                        console.log("[dlopen] unable to read path string");
                    }
                } catch (e) {
                    console.log("[dlopen] error reading path:", e.message);
                }
            },
            onLeave: function (retval) {
                // 可以在这里检查加载是否成功
                if (!retval.isNull()) {
                    // console.log("[dlopen] Success");
                } else {
                    console.log("[dlopen] Failed to load library");
                }
            }
        });
    }
    
    if (android_dlopen_ext) {
        Interceptor.attach(android_dlopen_ext, {
            onEnter: function (args) {
                this.path_ptr = args[0];
                
                if (!this.path_ptr || this.path_ptr.isNull()) {
                    console.log("[android_dlopen_ext] null path pointer");
                    return;
                }
                
                try {
                    var path = this.path_ptr.readCString();
                    if (path) {
                        console.log("[android_dlopen_ext] Loading:", path);
                    } else {
                        console.log("[android_dlopen_ext] unable to read path string");
                    }
                } catch (e) {
                    console.log("[android_dlopen_ext] error reading path:", e.message);
                }
            },
            onLeave: function (retval) {
                if (!retval.isNull()) {
                    // console.log("[android_dlopen_ext] Success");
                } else {
                    console.log("[android_dlopen_ext] Failed to load library");
                }
            }
        });
    }
});