//
// Created by khalegh on 9/5/20.
//

#include <ngx_core.h>

#ifndef IRONFOX_BOT_PROTECTION_H
#define IRONFOX_BOT_PROTECTION_H
struct attack {
    int count;
    char token[512];
    struct attack *next;
};
struct attack *head = NULL;

#define MODULE_VERSION  "0.1.0 The Desert Fox"

//todo review the challenges and model ( also obfuscation)
#define JS_MEDIUM_BODY "<html><head><title>IronFox</title></head><body><p style='text-align: center;'><span style='font-family:tahoma,geneva,sans-serif;'><span style='color: rgb(139, 69, 19);'><span style='font-size: 72px;'><span style='font-weight: bold;'>IronFox</span></span></span></span><br/><br/><span style='font-size:16px;'><font face='tahoma, geneva, sans-serif'><i>checking your request, This process is automatic and your browser redicret to your request content shortely.<br /><br/><span style='color:#000000;'>Please allow up for&nbsp;secondes...</span></i></font></span></p><p style='text-align: center;'>&nbsp;</p><hr/><p>&nbsp;</p><h2 style='text-align: center;'><span style='font-family:tahoma,geneva,sans-serif;'><span style='color:#2F4F4F;'><span style='font-size:14px;'>Powered by IronFox&nbsp;</span></span></span><br />&nbsp;</h2><script type='text/javascript' src='/iron.js'></script><script>var s='$bot_protection_enc_key$bot_protection_enc_salt$bot_protection_enc_iv$ironfox_cookie_enc_set$bot_protection_enc_salt';document.cookie ='IronFox=' + UTCString(s) + '; expires=' + TTL().toUTCString() + '; path=/';location.href = '$bot_protection_nexturl';</script></body></html>";
#define JS_MEDIUM_LEN 1174

#define JS_HARD_BODY   "<html><head><title>IronFox</title><script type='text/javascript' src='/sweet-alert.min.js'></script><link href='/sweet-alert.css' rel='stylesheet' type='text/css' /></head><body><p style='text-align: center;'><span style='font-family:tahoma,geneva,sans-serif;'><span style='color: rgb(139, 69, 19);'><span style='font-size: 72px;'><span style='font-weight: bold;'>IronFox</span></span></span></span><br/><br /><span style='font-size:16px;'><font face='tahoma, geneva, sans-serif'><i>checking your request, This process is automatic and your browser redicret to your request content shortely.<br/><br /><span style='color:#000000;'>Please allow up for&nbsp;secondes...</span></i></font></span></p><p style='text-align: center;'>&nbsp;</p><hr/><p>&nbsp;</p><h2 style='text-align: center;'><span style='font-family:tahoma,geneva,sans-serif;'><span style='color:#2F4F4F;'><span style='font-size:14px;'>Powered by IronFox&nbsp;</span></span></span><br/>&nbsp;</h2><script type='text/javascript' src='/iron.js'></script><script>var s='$bot_protection_enc_key$bot_protection_enc_salt$bot_protection_enc_iv$bot_protection_enc_set$bot_protection_enc_salt';sweetAlert({'title':'SUCESS!','type':'success','confirmButtonText':'Continue'},function(){var c={'laWCc':function(d,e){return d+e;},'kChpw':function(f,g){return f+g;},'OdryN':'IronFox=','iDxfA':function(h,i){return h(i);},'mgymq':';\\x20expires=','AEZta':function(j){return j();},'eGyhq':';\\x20path=/','AkAUa':'$bot_protection_nexturl'};document['cookie']=c['laWCc'](c['laWCc'](c['kChpw'](c['kChpw'](c['OdryN'],c['iDxfA'](UTCString,s)),c['mgymq']),c['AEZta'](TTL)['toUTCString']()),c['eGyhq']);location['href']=c['AkAUa'];});</script></body></html>";
#define JS_HARD_LEN 1694

#define JS_ENGIE_BODY  "<html><head><title>IronFox</title><script type='text/javascript' src='/sweet-alert.min.js'></script><link href='/sweet-alert.css' rel='stylesheet' type='text/css'/></head><body style='background-color:#ffffff;'><script type='text/javascript' src='/iron.js'></script><script>rasBigIntParser('$rnd0$bot_protection_enc_key$bot_protection_enc_salt$bot_protection_enc_iv$bot_protection_enc_set$bot_protection_enc_salt$rnd1','$bot_protection_nexturl');</script></body></html>";
#define JS_ENGIE_LEN 469

#define BOT_PROTECTION_OFF     0
#define BOT_PROTECTION_ON      1
#define BOT_PROTECTION_VARIABLE     2

// Wednesday, January 1, 2025 12:00:00 AM
#define NGX_HTTP_BOT_PROTECTION_TTL_MAX_EXPIRES  1735689600

#define ANOMALY_DETECTION_OFF     0
#define ANOMALY_DETECTION_ON     1

//todo make configurable
#define TOKEN_TTL_THRESHOLD_SECOND 30  // second
#define CSRF_BLOCKING_THRESHOLD 30      // 150 try
#define COOKIE_MAX_LENGTH 1024

#define DEFAULT_COOKIE_NAME "kooki"
#define TOKEN_NAME  "token="
#define TOKEN_NAME_LENGTH  6

#define KEY_NAME  "key="
#define KEY_NAME_LENGTH  4

#ifndef MD5_DIGEST_LENGTH
#define MD5_DIGEST_LENGTH 16
#endif
#define RFC1945_ATTEMPTS    4

#define PROBE_COOKIE_ENCRYPTION

#ifdef PROBE_COOKIE_ENCRYPTION

#include <openssl/rand.h>
#include <openssl/evp.h>

#endif

#define hextobin(c) ((c) >= 'A' && (c) <= 'F' ? c - 'A' + 10 : (c) >= 'a' && (c) <= 'f' ? c - 'a' + 10 : c - '0')

#endif //IRONFOX_BOT_PROTECTION_H
