#include <yara.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
static char output[65536]; static size_t used; static int matches;
static int callback(YR_SCAN_CONTEXT* ctx,int message,void* data,void* user){
 if(message==CALLBACK_MSG_RULE_MATCHING){YR_RULE* rule=(YR_RULE*)data;size_t n=strlen(rule->identifier);if(used+n+2>=sizeof(output))return CALLBACK_ABORT;memcpy(output+used,rule->identifier,n);used+=n;output[used++]='\n';output[used]=0;matches++;}return CALLBACK_CONTINUE;
}
int aw_scan(const unsigned char* data,int size,const char* source){
 YR_COMPILER* compiler=NULL;YR_RULES* rules=NULL;used=0;matches=0;output[0]=0;
 int code=yr_initialize();if(code!=ERROR_SUCCESS)return -1000-code;
 code=yr_compiler_create(&compiler);if(code!=ERROR_SUCCESS){yr_finalize();return -2000-code;}
 yr_compiler_set_include_callback(compiler,NULL,NULL,NULL);
 int errors=yr_compiler_add_string(compiler,source,"aw");if(errors){yr_compiler_destroy(compiler);yr_finalize();return -1;}
 code=yr_compiler_get_rules(compiler,&rules);if(code==ERROR_SUCCESS)code=yr_rules_scan_mem(rules,data,(size_t)size,SCAN_FLAGS_FAST_MODE,callback,NULL,10);
 if(rules)yr_rules_destroy(rules);yr_compiler_destroy(compiler);yr_finalize();
 return code==ERROR_SUCCESS?matches:-3000-code;
}
const char* aw_result(void){return output;}
