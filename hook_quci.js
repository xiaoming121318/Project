// com.smile.gifmaker  34366 quic pass

const quci = () => {
    // emergency_recovery.js - 修复崩溃并安全禁用QUIC
    Java.perform(function () {
        console.log('[紧急修复] 恢复应用并安全禁用QUIC');

        // 1. 首先，确保我们使用的是正确的 System 类
        var System = Java.use('java.lang.System');

        // 2. 恢复原生的 loadLibrary 方法（如果被修改过）
        try {
            System.loadLibrary.overload('java.lang.String').implementation = function (libname) {
                console.log(`[安全加载] ${libname}`);
                // 允许所有库正常加载
                return this.loadLibrary.call(this, libname);
            };
        } catch (e) {
            console.log('[注意] loadLibrary 可能已被其他代码修改');
        }

        // 3. 关键：找到并修改 isQuicEnabled 的正确方法
        // 先查找所有可能的配置类
        var configClasses = [];

        // 方法A：通过字符串特征查找
        var candidateClasses = [
            'com.kwai.link.IKlinkConfig',
            'com.kwai.link.KlinkConfig',
            'com.kwai.framework.network.cronet.CronetConfig',
            'com.kuaishou.aegon.AegonConfig',
            'com.kwai.quic.QuicConfig'
        ];

        candidateClasses.forEach(function (className) {
            try {
                var clazz = Java.use(className);
                console.log(`[找到] ${className}`);
                configClasses.push(clazz);
            } catch (e) {
                // 忽略不存在的类
            }
        });

        // 方法B：动态扫描
        if (configClasses.length === 0) {
            console.log('[扫描] 动态查找配置类...');
            Java.enumerateLoadedClasses({
                onMatch: function (className) {
                    // 查找包含特定关键词的类
                    var keywords = ['Config', 'Setting', 'Option', 'Param'];
                    var isConfigClass = keywords.some(function (keyword) {
                        return className.includes(keyword);
                    });

                    if (isConfigClass &&
                        (className.includes('kwai') ||
                            className.includes('kuaishou') ||
                            className.includes('link') ||
                            className.includes('network'))) {
                        try {
                            var clazz = Java.use(className);
                            console.log(`[候选] ${className}`);
                            configClasses.push(clazz);
                        } catch (e) {
                            // 忽略
                        }
                    }
                },
                onComplete: function () {
                    console.log(`[扫描完成] 找到 ${configClasses.length} 个候选类`);
                }
            });
        }

        // 4. 安全地 Hook 找到的配置类
        configClasses.forEach(function (clazz) {
            try {
                var className = clazz.$className;

                // 检查是否有 isQuicEnabled 方法
                var methods = clazz.class.getDeclaredMethods();
                var hasQuicMethod = false;

                for (var i = 0; i < methods.length; i++) {
                    var methodName = methods[i].getName();

                    // 匹配多种可能的命名
                    if (methodName.toLowerCase().includes('quic') ||
                        methodName === 'isQuicEnabled' ||
                        methodName === 'getQuicEnabled' ||
                        methodName === 'enableQuic') {

                        console.log(`[发现] ${className}.${methodName}()`);
                        hasQuicMethod = true;

                        // Hook 这个方法
                        clazz[methodName].implementation = function () {
                            console.log(`[QUIC禁用] ${className}.${methodName}() -> false`);
                            return false;
                        };
                    }
                }

                // 如果没有明确的QUIC方法，检查是否有enable开头的方法
                if (!hasQuicMethod) {
                    for (var j = 0; j < methods.length; j++) {
                        var methodName = methods[j].getName();
                        if (methodName.startsWith('enable') ||
                            methodName.startsWith('isEnable') ||
                            methodName.startsWith('getEnable')) {

                            // 检查返回类型
                            var returnType = methods[j].getReturnType().getName();
                            if (returnType === 'boolean') {
                                console.log(`[可能] ${className}.${methodName}() (返回boolean)`);

                                // 小心地Hook，记录但不修改
                                var originalMethod = clazz[methodName];
                                clazz[methodName].implementation = function () {
                                    var result = originalMethod.call(this);
                                    console.log(`[监控] ${className}.${methodName}() = ${result}`);
                                    return result; // 不修改，只监控
                                };
                            }
                        }
                    }
                }

            } catch (e) {
                console.log(`[跳过] ${clazz.$className}: ${e.message}`);
            }
        });

        // 5. 监控 Aegon 初始化但不阻止
        try {
            var Aegon = Java.use('com.kuaishou.aegon.Aegon');

            // 只监控，不修改
            Aegon.d.implementation = function (context, config, path, callback) {
                console.log(`[Aegon初始化] 配置: ${config}, 路径: ${path}`);

                // 修改配置字符串，添加禁用QUIC的参数
                if (config && typeof config === 'string') {
                    try {
                        var configObj = JSON.parse(config);
                        configObj.quic_enabled = false;
                        configObj.enable_quic = false;
                        configObj.enable_http3 = false;

                        var newConfig = JSON.stringify(configObj);
                        console.log(`[配置修改] ${config} -> ${newConfig}`);

                        // 使用修改后的配置
                        return this.d.call(this, context, newConfig, path, callback);
                    } catch (e) {
                        console.log('[配置解析失败] 使用原配置');
                    }
                }

                return this.d.call(this, context, config, path, callback);
            };

            console.log('[√] Aegon 监控成功');
        } catch (e) {
            console.log('[!] Aegon Hook 失败:', e.message);
        }

        // 6. 监控 Klink 构造函数
        try {
            var Klink = Java.use('com.kwai.link.Klink');

            Klink.$init.overload('android.content.Context',
                'com.kwai.link.IKlinkHost',
                'com.kwai.link.IKlinkConfig')
                .implementation = function (context, host, config) {
                    console.log('[Klink初始化] 开始');

                    // 这里只是监控，不修改行为
                    // 真正的修改已经在配置类层面完成了

                    return this.$init.call(this, context, host, config);
                };

            console.log('[√] Klink 监控成功');
        } catch (e) {
            console.log('[!] Klink Hook 失败:', e.message);
        }

        console.log('\n[完成] 紧急修复部署完成');
        console.log('[提示] 应用应该能正常启动，QUIC已被禁用');
    });
}

setImmediate(quci)
