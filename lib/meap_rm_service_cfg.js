var fs = require("fs");
var path = require("path");
var os = require("os");

function parseIP2Arr(ip) {
    var S = [],
        E = [];
    var iparr = ip.split("~");
    if (iparr.length > 1) {
        ca
        var arr = iparr[0].split(".");
        for (var i in arr)
            S[i] = parseInt(arr[i]);
        arr = iparr[1].split(".");
        for (var i in arr)
            E[i] = parseInt(arr[i]);
        return [S, E];
    } else {
        var arr = iparr[0].split(".");
        for (var i in arr) {
            if (arr[i] == "*") {
                S[i] = 0;
                E[i] = 255;
            } else {
                S[i] = E[i] = parseInt(arr[i]);
            }
        }
        return [S, E];
    }
    return null;
}

function parseIP(ip) {
    var arr = ip.split(".");
    var S = [];
    for (var i in arr)
        S[i] = parseInt(arr[i]);
    return S;
}

function compareIp(a, b) {
    try {
        for (var i = 0; i < 4; i++) {
            if (a[i] > b[i])
                return 1;
            else if (a[i] < b[i])
                return -1;
        }
    } catch (e) {
        _ERROR("[meap_rm_service_cfg][compareIp][ERROR] compareIp : ", e.message);
    }
    return 0;
}



function parseCfg(Context) {
    var context = Context;

    var serviceconfigpath = path.join(context.workpath, "service.json");
    var result = JSON.parse(fs.readFileSync(serviceconfigpath));
    context.Cache =  result.meap.cache;
    context.AuthPoolOption = result.meap.authpool;
    var ips = os.networkInterfaces();
    context.locationIP = null;
    for (var i in ips) {
        if (!context.locationIP && i.indexOf("lo") == -1) {
            context.locationIP = ips[i][0]['address'];
        }
    }

    context.hostname = os.hostname();
    context.Logstate = result.meap.logstate;
    context.Log = result.meap.log;

    context.Options = {};
    context.Options.servicename = result.meap.servicename;

  //  RewriteLog(context);
    try {
        context.Services = {};
        context.SessionPool = {};
        try {
            process.env.TMP = result.meap.tmpdir ? result.meap.tmpdir : "/tmp";

            // var masConf = JSON.parse(fs.readFileSync('/etc/MAS.conf  '));
            context.Options.serviceinfo = result.meap.serviceinfo;
            context.Options.cacache = result.meap.cacache;

            //自定义缓存池
            context.customCache = result.meap.customCache;
            context.Cookie = result.meap.cookie;
            context.InterfaceDir = result.meap.interfacedir;
            context.CounterPower = result.meap.counterPower;
            context.CountermonitorDB = result.meap.counterMonitor;
            context.AppPolicyPower = result.meap.appPolicyPower;
            context.AppValidTime = result.meap.appValidTime * 1000 || 600000;
            context.IfPolicyPower = result.meap.ifPolicyPower;
            context.ServiceThreshold = result.meap.threshold;

            for (var j in context.ServiceThreshold) {
                context.ServiceThreshold[j] = parseInt(context.ServiceThreshold[j]);
            }

            context.MaxConcurrent = result.meap.maxConcurrent;
            context.MessageThreshold = {
                service: {},
                app: {},
                appuser: {},
                appip: {}
            };
            context.Options.Servers = [];
            context.Projects = result.meap.projects;

            if (!result.meap.sessionpool) {
                context.SessionPool.Switch = false;
            } else {
                context.SessionPool.Switch = result.meap.sessionpool["switch"];
                context.SessionPool.Running = result.meap.sessionpool.running ? parseInt(result.meap.sessionpool.running) : 500;
                context.SessionPool.Waitting = result.meap.sessionpool.waiting ? parseInt(result.meap.sessionpool.waiting) : 500;
                context.SessionPool.Timeout = result.meap.sessionpool.Timeout ? parseInt(result.meap.sessionpool.Timeout) : 30;
            }
        } catch (e) {
            _ERROR("[meap_rm_service_cfg][parseCfg][ERROR]: parseCfg " + e.message);
        }

        if (!Array.isArray(result.meap.services)) {
            var temp = result.meap.services;
            result.meap.services = [temp];
        }
        for (var serv in result.meap.services) {
            var settings = result.meap.services[serv];
            var serviceName = settings.name;
            var Service = {
                protocal: "HTTP",
                port: 13000,
                host: "0.0.0.0",
                secure: false,
                ippolicy: null,
                auth: null,
                timeout: 60,
                localhost: "0.0.0.0"
            };
            {
                if (settings.timeout)
                    Service.timeout = parseInt(settings.timeout) ? parseInt(settings.timeout) : 60;
                Service.secure = settings.secure;
                Service["switch"] = settings["switch"] ? settings["switch"] : "open";
                if (settings.host)
                    Service.host = settings.host;
                if (settings.port)
                    Service.port = settings.port;
                if (settings.protocal)
                    Service.protocal = settings.protocal;
                if (Service.protocal == "HTTPS") {
                    var keypath = path.join(context.configpath, settings.certificate.key);
                    var certpath = path.join(context.configpath, settings.certificate.cert);
                    if (settings.certificate.key.indexOf("/") == 0 || settings.certificate.key.indexOf("://") > 0) {
                        keypath = settings.certificate.key;
                    }
                    if (settings.certificate.cert.indexOf("/") == 0 || settings.certificate.cert.indexOf("://") > 0) {
                        certpath = settings.certificate.cert;
                    }
                    Service.cert = {
                        key: keypath,
                        cert: certpath
                    }
                }
                if (settings.secure) {
                    var auth = {
                        type: settings.auth.type
                    };
                    switch (settings.auth.type) {
                        case "basic":
                            auth.username = settings.auth.username;
                            auth.password = settings.auth.password;
                            break;
                        case "ssl":
                            auth.ca = path.join(context.configpath, settings.auth.ca);
                            if (settings.auth.ca.indexOf("/") == 0 || settings.auth.ca.indexOf("://") > 0) {
                                auth.ca = settings.auth.ca;
                            }
                            break;
                        default:
                            break;
                    }
                    Service.auth = auth;
                }
                if (settings["ip-policy"]) {
                    Service.ippolicy = settings["ip-policy"].type;
                    var hosts = settings["ip-policy"].host.split(";");
                    Service.hosts = [];
                    for (var i in hosts) {
                        var iprange = parseIP2Arr(hosts[i]);
                        if (iprange)
                            Service.hosts.push(iprange);
                    }
                }
                Service.subservicename = settings.subservicename;
            }
            if (!context.Services[serviceName])
                context.Services[serviceName] = [];
            context.Services[serviceName].push(Service);
            if (Service["switch"] == "open") {
                context.Options.Servers.push({
                    subservicename: Service.subservicename
                });
            }
        }

        function globalMonitor(context) {
            var option = {
                host: context.CountermonitorDB.host,
                port: context.CountermonitorDB.port,
                db: context.CountermonitorDB.db,
                authpass: context.CountermonitorDB.authpass
            }

        }

        globalMonitor(context);

        var counterOption = {
            host: context.CountermonitorDB.host,
            port: context.CountermonitorDB.port,
            db: context.CountermonitorDB.db,
            authpass: context.CountermonitorDB.authpass
        }
        context.CounterPublish = {};

        var transinfo = {
            maxtime: {},
            mintime: {},
            count: 0,
            err: 0,
            size: 0
        };

        function makeTransSummary(CountObject) {
            var counter = 0;
            var length = 0;
            for (var i in transinfo.maxtime) {
                if (transinfo.maxtime[i] > CountObject.responsetime)
                    counter++;
                length++;
            }
            if (counter < 5) {
                if (transinfo.maxtime[CountObject.cmd] == undefined)
                    transinfo.maxtime[CountObject.cmd] = CountObject.responsetime;
                if (transinfo.maxtime[CountObject.cmd] < CountObject.responsetime)
                    transinfo.maxtime[CountObject.cmd] = CountObject.responsetime;

                if (length >= 5) {
                    var maxitem = null;
                    var maxtime = 0;
                    for (var i in transinfo.maxtime) {
                        if (transinfo.maxtime[i] < maxtime || maxtime == 0) {
                            maxtime = transinfo.maxtime[i];
                            maxitem = i;
                        }
                    }
                    delete transinfo.maxtime[maxitem];
                }
            }
            counter = 0;
            length = 0;
            for (var i in transinfo.mintime) {
                if (transinfo.mintime[i] < CountObject.responsetime)
                    counter++;
                length++;
            }
            if (counter < 5) {
                if (transinfo.mintime[CountObject.cmd] == undefined)
                    transinfo.mintime[CountObject.cmd] = CountObject.responsetime;
                if (transinfo.mintime[CountObject.cmd] > CountObject.responsetime)
                    transinfo.mintime[CountObject.cmd] = CountObject.responsetime;
                if (length >= 5) {
                    var minitem = null;
                    var mintime = 0;
                    for (var i in transinfo.mintime) {
                        if (transinfo.mintime[i] > mintime) {
                            mintime = transinfo.mintime[i];
                            minitem = i;
                        }
                    }
                    delete transinfo.mintime[minitem];
                }
            }
            transinfo.count++;
            CountObject.err != 0 && transinfo.err++;
            transinfo.size += CountObject.size;
        }
    } catch (e) {
        console.log(e)
        _ERROR("[meap_rm_service_cfg][parseCfg][ERROR]: Parse service config fail. " + e.message);
    }
}

exports.Runner = parseCfg;
exports.ParseIP = parseIP;
exports.CompareIP = compareIp;
