#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <dlfcn.h>

static BOOL retYES(id s, SEL c){ return YES; }
static BOOL retNO(id s, SEL c){ return NO; }
static id retNil(id s, SEL c){ return nil; }
static double retFuture(id s, SEL c){ return 4102444799.0; }
static void noop0(id s, SEL c){ }
static void noop1(id s, SEL c, id a){ }
static void noop2(id s, SEL c, id a, id b){ }
static void noop3(id s, SEL c, id a, id b, id c2){ }
static long ret0(id s, SEL c){ return 0; }

static void dumpAll(void){
  int n=objc_getClassList(NULL,0);
  Class *cls=(Class*)calloc(n,sizeof(Class));
  n=objc_getClassList(cls,n);
  NSMutableString *out=[NSMutableString string];
  for(int i=0;i<n;i++){
    Class K=cls[i];
    Dl_info di; if(!dladdr((__bridge void*)K,&di)||!di.dli_fname) continue;
    NSString *p=[NSString stringWithUTF8String:di.dli_fname];
    if(!([p containsString:@"Podcasts.app"]||[p containsString:@"StarbucksSTE"])) continue;
    [out appendFormat:@"\n== %s ==\n",class_getName(K)];
    unsigned mc=0; Method *ms=class_copyMethodList(K,&mc);
    for(unsigned j=0;j<mc;j++){
      [out appendFormat:@"  %s  %s\n",sel_getName(method_getName(ms[j])),method_getTypeEncoding(ms[j])];
    }
    free(ms);
  }
  free(cls);
  [out writeToFile:@"/var/mobile/stehook_dump.txt" atomically:YES encoding:NSUTF8StringEncoding error:nil];
  NSLog(@"[STE] dump %lu classes written",(unsigned long)n);
}

static void sweep(void){
  int n=objc_getClassList(NULL,0);
  Class *cls=(Class*)calloc(n,sizeof(Class));
  n=objc_getClassList(cls,n);
  for(int i=0;i<n;i++){
    Class K=cls[i];
    Dl_info di; if(!dladdr((__bridge void*)K,&di)||!di.dli_fname) continue;
    NSString *p=[NSString stringWithUTF8String:di.dli_fname];
    if(!([p containsString:@"Podcasts.app"]||[p containsString:@"StarbucksSTE"])) continue;
    unsigned mc=0; Method *ms=class_copyMethodList(K,&mc);
    for(unsigned j=0;j<mc;j++){
      SEL sel=method_getName(ms[j]); NSString *s=[NSString stringWithUTF8String:sel_getName(sel)];
      const char *te=method_getTypeEncoding(ms[j]);
      BOOL isBool = te[0]=='c' || te[0]=='B';
      // 失败/无效类判定 -> NO
      if(isBool && ([s hasPrefix:@"responseMessageIndicatesLoginFailure"]||
                    [s hasPrefix:@"responseIndicatesSessionInvalid"]||
                    [s hasPrefix:@"messageMeansInvalidSession"]||
                    [s hasPrefix:@"messageIndicatesSessionInvalid"]||
                    [s hasPrefix:@"isExpired"]||[s hasPrefix:@"isInvalid"]||
                    [s hasPrefix:@"isBanned"]||[s hasPrefix:@"isFrozen"]||
                    [s hasPrefix:@"_isInvalid"]||[s hasPrefix:@"shouldShowExpired"]||
                    [s hasPrefix:@"isUnauthorized"])){
        method_setImplementation(ms[j],(IMP)retNO);
      } else if(isBool && ([s hasPrefix:@"hasValid"]||[s hasPrefix:@"isValid"]||
                    [s hasPrefix:@"isVIP"]||[s hasPrefix:@"isAuthorized"]||
                    [s hasPrefix:@"isActivated"]||[s hasPrefix:@"hasSavedCard"]||
                    [s hasPrefix:@"hasValidCore"]||[s hasPrefix:@"hasValidFeature"]||
                    [s hasPrefix:@"canUse"]||[s hasPrefix:@"isUsable"])){
        method_setImplementation(ms[j],(IMP)retYES);
      }
      // 到期时间 -> 2099
      if([s containsString:@"ExpiresAt"]||[s containsString:@"ExpireTime"]||
         [s isEqualToString:@"coreLeaseExpiresAt"]||[s isEqualToString:@"featureLeaseExpiresAt"]||
         [s isEqualToString:@"vipExpireTime"]||[s isEqualToString:@"secureExpiresAt"]){
        if(te[0]=='d') method_setImplementation(ms[j],(IMP)retFuture);
      }
      // 到期弹窗/退出 -> 空
      if([s hasPrefix:@"_showExpiredAlert"]||[s hasPrefix:@"showExpired"]) {
        if(te[0]=='v'){ if(te[2]=='@') method_setImplementation(ms[j],(IMP)noop1); else method_setImplementation(ms[j],(IMP)noop0);}
      }
      // 卡密 token/明细返回非空? 让 savedCard/activeCard 返回占位
    }
    free(ms);
  }
  free(cls);
  NSLog(@"[STE] sweep done");
}

__attribute__((constructor))
static void ste_init(void){
  dumpAll();
  sweep();
}
