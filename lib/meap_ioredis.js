//兼容以前的redis 采取新的ioredis by daizhiyu

var Crypto = require("crypto");
var Redis=require('ioredis');

function CacheControlIORedis(res) {
    var CC = {
        //https://www.cnblogs.com/waruzhi/p/3831089.html
        LM: res.headers["last-modified"], //If-Modified-Since
        //HTTP响应头是资源的特定版本的标识符。这可以让缓存更高效，并节省带宽，因为如果内容没有改变，Web服务器不需要发送完整的响应。而如果内容发生了变化，使用ETag有助于防止资源的同时更新相互覆盖（“空中碰撞”）。
        ETAG: res.headers["etag"], //If-None-Match HTTP协议规格说明定义ETag为“被请求变量的实体值” ETag是一个可以与Web资源关联的记号（token）
        EXP: res.headers["expires"]
    }; //Expires
    return (CC.LM || CC.ETAG || CC.EXP) ? CC : null;


}

function CacheManIORedis(Context,auth) {
    LOG3("[meap_ioredis][CacheMan] CacheMan created ", Context.Cache);
    var self = this;
    var option;
    if(auth){
        option = Context.AuthPoolOption;
    }else {
        option = Context.Cache;
    }
     self.redis=new Redis(option);
}

CacheManIORedis.prototype.saveCache = function (url, st, cc, cache, cacheTime) {
    LOG3("[meap_cacheman_ioredis][CacheMan] saveCache [key] [st]", url,st);
    var self = this;
    var m = Crypto.createHash('md5');
    m.update(url);
    m.update(st);
    var key = m.digest('hex');
    var item = {};
    item[st] = JSON.stringify(cc);
    item[st + "cache"] = cache;

    self.redis.hmset("cache~" + key,item).then(function (result) {
        if (cacheTime) {
            self.redis.expire("cache~" + key, cacheTime);
        }
    });
}
CacheManIORedis.prototype.getCacheControl = function (url, st, cb) {
    LOG3("[meap_cacheman_ioredis][CacheMan] getCacheControl [key] [st]", url,st);
    var self = this;
    var m = Crypto.createHash('md5');
    m.update(url);
    m.update(st);
    var key = m.digest('hex');
    self.redis.hget("cache~" + key,st).then(function (result) {
        if (cb)
            cb(0, result);
    })
}

CacheManIORedis.prototype.getCache = function (url, st, cb) {
    LOG3("[meap_cacheman_ioredis][CacheMan] getCache [key] [st]", url,st);
    var self = this;
    var m = Crypto.createHash('md5');
    m.update(url);
    m.update(st);
    var key = m.digest('hex');
    self.redis.hget("cache~" + key, st + "cache").then(function (result) {
        if (cb)
            cb(0, result);
    })
}


module.exports.CacheManIORedis = CacheManIORedis;
module.exports.CacheControlIORedis = CacheControlIORedis;
